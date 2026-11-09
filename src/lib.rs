//! X-Wing, the hybrid KEM of ML-KEM-768 and X25519 (draft-connolly-cfrg-xwing-kem-11), for
//! microcontrollers.
//!
//! - ML-KEM-768 and X25519 are the traits [`MlKem768`] and [`X25519`], so a target can use its
//!   own implementations, for example in assembly. The cargo features `mlkem-otf`, `ml-kem` and
//!   `x25519-dalek` provide software implementations, and `x25519-cortex-m` an X25519 in Cortex-M
//!   assembly.
//! - A decapsulation key is expanded once with [`XWing::expand`] and a peer's encapsulation key
//!   is checked once with [`XWing::check`]. Both borrow the encapsulation key where it is
//!   stored or received, for example in flash or in a packet.
//! - Secret keys are filled in place, in a [`DecapsulationKeySlot`] or an [`ExpandedKeySlot`]
//!   that the caller provides, and only lent out by shared reference, so they are never moved.
//! - Ciphertexts and encapsulation keys are written into the caller's buffer.
//!
//! No allocation, and secrets are wiped on drop.
//!
//! ```
//! use static_cell::ConstStaticCell;
//! use xwing_embedded::{
//!     Ciphertext, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, ExpandedKeySlot,
//!     OtfMlKem768, SoftwareXWing,
//! };
//! # use rand_core::{Rng, SeedableRng};
//! # let rng = &mut chacha20::ChaCha20Rng::from_seed([0; 32]);
//! # let mut storage = [0; 32];
//! # rng.fill_bytes(&mut storage);
//!
//! let kem = &mut SoftwareXWing::default();
//!
//! // Provisioning: store the seed in secure storage and the encapsulation key where it can be
//! // read. The slot on the stack is wiped when it is dropped.
//! let mut seed = storage;
//! let mut slot = DecapsulationKeySlot::new();
//! let secret_key = DecapsulationKey::from_seed(&mut slot, &mut seed);
//! let mut public = EncapsulationKey::from([0; 1216]);
//! kem.encapsulation_key(secret_key, &mut public);
//! drop(slot);
//!
//! // At start: load the seed, which wipes `seed`, and expand it once into a static slot
//! static KEY: ConstStaticCell<ExpandedKeySlot<OtfMlKem768>> =
//!     ConstStaticCell::new(ExpandedKeySlot::new());
//! let mut seed = storage;
//! let mut slot = DecapsulationKeySlot::new();
//! let secret_key = DecapsulationKey::from_seed(&mut slot, &mut seed);
//! let own = kem.expand(KEY.take(), secret_key, &public)?;
//! drop(slot);
//!
//! // A peer checks the encapsulation key once and encapsulates to it
//! let peer = kem.check(&public)?;
//! let mut ciphertext = Ciphertext::from([0; 1120]);
//! let sent = kem.encapsulate(rng, &peer, &mut ciphertext);
//!
//! let received = kem.decapsulate(&own, &ciphertext);
//! assert_eq!(sent.expose_secret(), received.expose_secret());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
#![cfg_attr(not(test), no_std)]

#[cfg(all(feature = "x25519-cortex-m", not(cortex_m_dsp)))]
compile_error!(
    "the `x25519-cortex-m` feature needs ARMv7E-M (thumbv7em-*) or ARMv8-M Mainline with DSP \
     (thumbv8m.main-* with `-C target-cpu=cortex-m33` or another core with DSP)"
);

#[cfg(all(feature = "x25519-cortex-m", cortex_m_dsp))]
#[allow(unsafe_code)]
mod cortex_m;
#[cfg(feature = "x25519-dalek")]
mod dalek;
mod mlkem;
#[cfg(feature = "mlkem-otf")]
mod otf;
#[cfg(feature = "ml-kem")]
mod rustcrypto;
mod x25519;

#[cfg(all(feature = "x25519-cortex-m", cortex_m_dsp))]
pub use cortex_m::CortexMX25519;
#[cfg(feature = "x25519-dalek")]
pub use dalek::DalekX25519;
pub use mlkem::{MlKem768, MlKemSharedSecret};
#[cfg(feature = "mlkem-otf")]
pub use otf::OtfMlKem768;
#[cfg(feature = "ml-kem")]
pub use rustcrypto::{
    RustCryptoCheckedKey, RustCryptoExpandedKey, RustCryptoKeySlot, RustCryptoMlKem768,
};
pub use x25519::{X25519, X25519PublicKey, X25519SecretKey, X25519SharedSecret};

use derive_more::{AsMut, AsRef, From};
use derive_where::derive_where;
use rand_core::{CryptoRng, TryCryptoRng};
use sha3::{Digest, Sha3_256};
use shake::{Shake256, Update, XofReader, digest::ExtendableOutputReset};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute_mut, transmute_ref,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// `XWingLabel`, draft section 5.3.
const LABEL: &[u8; 6] = br"\.//^\";

/// A decapsulation key, the 32-byte seed every part of the key is expanded from (draft section
/// 5.2).
///
/// It is filled in place in a [`DecapsulationKeySlot`] and only lent out by shared reference, so
/// it is never moved.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey([u8; 32]);

/// Where a [`DecapsulationKey`] lives, for example on the stack while the key is expanded. A slot
/// that holds no key yet holds zeros, and the key is only reachable through the constructors of
/// [`DecapsulationKey`]. Wiped when dropped. Moving a slot that holds a key copies the key, so
/// keep the slot where it is.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKeySlot(DecapsulationKey);

impl DecapsulationKeySlot {
    /// An empty slot.
    pub const fn new() -> Self {
        Self(DecapsulationKey([0; 32]))
    }

    /// The key in the slot, wiped to be filled in place.
    fn wiped(&mut self) -> &mut DecapsulationKey {
        self.zeroize();
        &mut self.0
    }
}

impl Default for DecapsulationKeySlot {
    fn default() -> Self {
        Self::new()
    }
}

impl DecapsulationKey {
    /// Loads a uniformly random seed, for example a stored one, into `slot`, and wipes `seed`. A
    /// key already in `slot` is wiped first.
    pub fn from_seed<'s>(slot: &'s mut DecapsulationKeySlot, seed: &mut [u8; 32]) -> &'s Self {
        let key = slot.wiped();
        key.0.copy_from_slice(seed);
        seed.zeroize();
        key
    }

    /// Draws a new seed from `rng` into `slot`. A key already in `slot` is wiped first. The seed
    /// cannot be read back, so this is for keys that are not stored. To store a key, draw the
    /// seed and use [`Self::from_seed`].
    pub fn generate<'s>(slot: &'s mut DecapsulationKeySlot, rng: &mut impl CryptoRng) -> &'s Self {
        let Ok(key) = Self::try_generate(slot, rng);
        key
    }

    /// [`Self::generate`] with an RNG that can fail. On an error the slot is wiped.
    pub fn try_generate<'s, R: TryCryptoRng + ?Sized>(
        slot: &'s mut DecapsulationKeySlot,
        rng: &mut R,
    ) -> Result<&'s Self, R::Error> {
        let key = slot.wiped();
        match rng.try_fill_bytes(&mut key.0) {
            Ok(()) => Ok(key),
            Err(e) => {
                key.zeroize();
                Err(e)
            }
        }
    }
}

/// An encapsulation key, `pk_M || pk_X` (draft section 5.2). Unchecked, see [`XWing::check`].
#[derive(Clone, Debug, PartialEq, Eq, From, AsRef, AsMut)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(
    feature = "zerocopy",
    derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)
)]
#[repr(transparent)]
pub struct EncapsulationKey([u8; 1216]);

/// A ciphertext, `ct_M || ct_X` (draft section 5.4).
#[derive(Clone, Debug, PartialEq, Eq, From, AsRef, AsMut)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(
    feature = "zerocopy",
    derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)
)]
#[repr(transparent)]
pub struct Ciphertext([u8; 1120]);

/// The shared secret of one encapsulation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Wraps known bytes, for tests of what consumes a shared secret.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The secret, for a key schedule.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// ML-KEM-768 rejected an encapsulation key (FIPS 203 section 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("invalid ML-KEM-768 encapsulation key")]
pub struct InvalidEncapsulationKey;

/// The encapsulation key is not the one of the decapsulation key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[error("encapsulation key does not match the decapsulation key")]
pub struct KeyMismatch;

/// Where an [`ExpandedKey`] keeps its secrets, for example in a `static`, a `ConstStaticCell` or
/// on the stack. A slot that holds no key yet holds zeros, and the key is only reachable through
/// [`XWing::expand`]. Wiped when dropped. Moving a slot that holds a key copies the key, so keep
/// the slot where it is.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExpandedKeySlot<M: MlKem768> {
    ml_kem: M::KeySlot,
    x25519: X25519SecretKey,
}

impl<M: MlKem768> ExpandedKeySlot<M> {
    /// An empty slot.
    pub const fn new() -> Self {
        Self {
            ml_kem: M::EMPTY_SLOT,
            x25519: X25519SecretKey([0; 32]),
        }
    }
}

impl<M: MlKem768> Default for ExpandedKeySlot<M> {
    fn default() -> Self {
        Self::new()
    }
}

/// A decapsulation key expanded once for every decapsulation with it. It borrows the secrets from
/// its [`ExpandedKeySlot`] and its encapsulation key, and holds no secret of its own.
///
/// It is invariant in `'a`, so a borrow of it needs a second lifetime, `&'b ExpandedKey<'a, M>`.
pub struct ExpandedKey<'a, M: MlKem768> {
    ml_kem: M::ExpandedKey<'a>,
    x25519: &'a X25519SecretKey,
    own: &'a [u8; 32],
}

/// An encapsulation key that passed [`XWing::check`], which borrows it.
#[derive_where(Clone, Debug; M::CheckedKey<'k>)]
pub struct CheckedKey<'k, M: MlKem768> {
    ml_kem: M::CheckedKey<'k>,
    x25519: &'k [u8; 32],
}

/// X-Wing over an ML-KEM-768 and an X25519 implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct XWing<M, X> {
    /// The ML-KEM-768 implementation.
    pub ml_kem: M,
    /// The X25519 implementation.
    pub x25519: X,
}

/// [`EncapsulationKey`] split into its components, draft section 5.2.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct EncapsulationKeyParts {
    ml_kem: [u8; 1184],
    x25519: [u8; 32],
}

/// [`Ciphertext`] split into its components, draft section 5.4.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct CiphertextParts {
    ml_kem: [u8; 1088],
    x25519: [u8; 32],
}

/// Writes `SHAKE256(key, 96 * 8)` (draft section 5.2) in place, `d || z` to `ml_kem` and `sk_X`
/// to `x25519`.
fn expand_seed(key: &DecapsulationKey, ml_kem: &mut [u8; 64], x25519: &mut X25519SecretKey) {
    let mut xof = Shake256::default();
    xof.update(&key.0);
    // The reader gets a copy of the state, which holds `key` until the first read permutes it.
    // The residue checks of `make test-qemu` show that no copy of `key` stays on the stack.
    let mut reader = xof.finalize_xof_reset();
    reader.read(ml_kem);
    reader.read(&mut x25519.0);
}

/// `Combiner`, draft section 5.3. Fed in parts, so there is no input buffer to wipe.
fn combiner(
    ml_kem: &MlKemSharedSecret,
    x25519: &X25519SharedSecret,
    ciphertext: &[u8; 32],
    public: &[u8; 32],
) -> SharedSecret {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, ml_kem.expose_secret());
    Digest::update(&mut hasher, x25519.expose_secret());
    Digest::update(&mut hasher, ciphertext);
    Digest::update(&mut hasher, public);
    Digest::update(&mut hasher, LABEL);
    let mut secret = Zeroizing::new([0; 32]);
    // In place, since a by-value finalize can leave an unwiped copy of the state
    Digest::finalize_into_reset(&mut hasher, (&mut *secret).into());
    SharedSecret(*secret)
}

impl<M: MlKem768, X: X25519> XWing<M, X> {
    /// Writes the encapsulation key of `key` to `out`, for provisioning.
    pub fn encapsulation_key(&mut self, key: &DecapsulationKey, out: &mut EncapsulationKey) {
        let mut seed = Zeroizing::new([0; 64]);
        let mut x25519 = X25519SecretKey([0; 32]);
        expand_seed(key, &mut seed, &mut x25519);
        let parts: &mut EncapsulationKeyParts = transmute_mut!(&mut out.0);
        self.ml_kem.encapsulation_key(&mut seed, &mut parts.ml_kem);
        parts.x25519 = self.x25519.public_key(&x25519).into();
    }

    /// Expands `key` into `slot` for decapsulation (`expandDecapsulationKey`, draft section
    /// 5.2), and checks that `own` is its encapsulation key. A key already in `slot` is wiped
    /// first. On an error `slot` keeps what was filled in until it is filled again or dropped.
    pub fn expand<'a>(
        &mut self,
        slot: &'a mut ExpandedKeySlot<M>,
        key: &DecapsulationKey,
        own: &'a EncapsulationKey,
    ) -> Result<ExpandedKey<'a, M>, KeyMismatch> {
        slot.zeroize();
        let ExpandedKeySlot { ml_kem, x25519 } = slot;
        let mut seed = Zeroizing::new([0; 64]);
        expand_seed(key, &mut seed, x25519);
        let own: &EncapsulationKeyParts = transmute_ref!(&own.0);
        // Both keys are public, so the comparison need not be constant time
        if self.x25519.public_key(x25519) != X25519PublicKey::from(own.x25519) {
            return Err(KeyMismatch);
        }
        Ok(ExpandedKey {
            ml_kem: self.ml_kem.expand(ml_kem, &mut seed, &own.ml_kem)?,
            x25519,
            own: &own.x25519,
        })
    }

    /// Checks a peer's encapsulation key once, so encapsulating to it cannot fail.
    pub fn check<'k>(
        &mut self,
        key: &'k EncapsulationKey,
    ) -> Result<CheckedKey<'k, M>, InvalidEncapsulationKey> {
        let key: &EncapsulationKeyParts = transmute_ref!(&key.0);
        Ok(CheckedKey {
            ml_kem: self.ml_kem.check(&key.ml_kem)?,
            x25519: &key.x25519,
        })
    }

    /// Encapsulates to `peer`, writing the ciphertext to `ciphertext` (`Encapsulate`, draft
    /// section 5.4).
    pub fn encapsulate(
        &mut self,
        rng: &mut impl CryptoRng,
        peer: &CheckedKey<'_, M>,
        ciphertext: &mut Ciphertext,
    ) -> SharedSecret {
        let Ok(secret) = self.try_encapsulate(rng, peer, ciphertext);
        secret
    }

    /// [`Self::encapsulate`] with an RNG that can fail. On an error `ciphertext` is left as it
    /// was.
    pub fn try_encapsulate<R: TryCryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        peer: &CheckedKey<'_, M>,
        ciphertext: &mut Ciphertext,
    ) -> Result<SharedSecret, R::Error> {
        // `eseed = m || ek_X`, each read in place
        let mut m = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(&mut *m)?;
        let mut ephemeral = X25519SecretKey([0; 32]);
        rng.try_fill_bytes(&mut ephemeral.0)?;

        let parts: &mut CiphertextParts = transmute_mut!(&mut ciphertext.0);
        parts.x25519 = self.x25519.public_key(&ephemeral).into();
        let x25519 = self
            .x25519
            .shared_secret(&ephemeral, &(*peer.x25519).into());
        let ml_kem = self.ml_kem.encapsulate(&peer.ml_kem, &m, &mut parts.ml_kem);
        Ok(combiner(&ml_kem, &x25519, &parts.x25519, peer.x25519))
    }

    /// Decapsulates `ciphertext` (`Decapsulate`, draft section 5.5). Never fails, since a
    /// tampered ciphertext gives an unrelated secret.
    pub fn decapsulate(
        &mut self,
        key: &ExpandedKey<'_, M>,
        ciphertext: &Ciphertext,
    ) -> SharedSecret {
        let parts: &CiphertextParts = transmute_ref!(&ciphertext.0);
        let ml_kem = self.ml_kem.decapsulate(&key.ml_kem, &parts.ml_kem);
        let x25519 = self.x25519.shared_secret(key.x25519, &parts.x25519.into());
        combiner(&ml_kem, &x25519, &parts.x25519, key.own)
    }
}

/// X-Wing with the software ML-KEM-768 and X25519 of the default features.
#[cfg(all(feature = "mlkem-otf", feature = "x25519-dalek"))]
pub type SoftwareXWing = XWing<OtfMlKem768, DalekX25519>;
