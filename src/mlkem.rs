//! The ML-KEM-768 component.

use crate::{InvalidEncapsulationKey, KeyMismatch};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 (FIPS 203). Byte strings are the FIPS 203 encodings.
///
/// Keys and ciphertexts are written into the caller's buffer. The secret of an expanded key is
/// filled in place into a [`Self::KeySlot`], which the caller provides, so it is never moved.
/// Expanded and checked keys may borrow the encapsulation key where it is stored or received, so
/// an implementation can stream over it instead of keeping a decoded copy.
pub trait MlKem768 {
    /// Where an expanded key keeps its secret.
    type KeySlot: Zeroize + ZeroizeOnDrop;
    /// What decapsulation needs of a decapsulation key and its encapsulation key. It is returned
    /// by value, so it borrows the secret from its [`Self::KeySlot`] and holds none of its own.
    type ExpandedKey<'a>;
    /// What encapsulation keeps of a checked encapsulation key.
    type CheckedKey<'k>;

    /// A slot that holds no key.
    const EMPTY_SLOT: Self::KeySlot;

    /// Writes the encapsulation key of `seed = d || z` to `out` (`ML-KEM.KeyGen_internal`,
    /// FIPS 203 Algorithm 16). The caller wipes `seed` after the call, so the implementation may
    /// overwrite it.
    fn encapsulation_key(&mut self, seed: &mut [u8; 64], out: &mut [u8; 1184]);

    /// Expands `seed = d || z` for decapsulation into `slot`, which holds no key, and checks that
    /// `own` is its encapsulation key. The caller wipes `seed` after the call, so the
    /// implementation may overwrite it.
    fn expand<'a>(
        &mut self,
        slot: &'a mut Self::KeySlot,
        seed: &mut [u8; 64],
        own: &'a [u8; 1184],
    ) -> Result<Self::ExpandedKey<'a>, KeyMismatch>;

    /// The encapsulation key check of FIPS 203 section 7.2.
    fn check<'k>(
        &mut self,
        key: &'k [u8; 1184],
    ) -> Result<Self::CheckedKey<'k>, InvalidEncapsulationKey>;

    /// `ML-KEM.Encaps_internal(ek, m)` (FIPS 203 Algorithm 17) to `peer`, writing the
    /// ciphertext to `ciphertext`.
    fn encapsulate(
        &mut self,
        peer: &Self::CheckedKey<'_>,
        m: &[u8; 32],
        ciphertext: &mut [u8; 1088],
    ) -> MlKemSharedSecret;

    /// `ML-KEM.Decaps_internal(dk, c)` (FIPS 203 Algorithm 18), with implicit rejection.
    fn decapsulate(
        &mut self,
        key: &Self::ExpandedKey<'_>,
        ciphertext: &[u8; 1088],
    ) -> MlKemSharedSecret;
}

/// The shared secret of one ML-KEM-768 encapsulation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret([u8; 32]);

impl MlKemSharedSecret {
    /// Wraps the result of an [`MlKem768`] implementation.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The secret, for the X-Wing combiner.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}
