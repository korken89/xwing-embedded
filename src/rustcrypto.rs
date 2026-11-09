//! ML-KEM-768 from the RustCrypto `ml-kem` crate.

use crate::{InvalidEncapsulationKey, KeyMismatch, MlKem768, MlKemSharedSecret};
use ml_kem::{Decapsulate, KeyExport, ml_kem_768};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ML-KEM-768 in software, from the RustCrypto `ml-kem` crate. It keeps the decoded keys, so
/// it needs more RAM and stack than a streaming implementation.
///
/// The `ml-kem` crate returns the decoded decapsulation key by value, so `expand` and
/// `encapsulation_key` leave copies of it on the stack.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RustCryptoMlKem768;

/// The key slot of [`RustCryptoMlKem768`], for the decoded decapsulation key.
pub struct RustCryptoKeySlot(Option<ml_kem_768::DecapsulationKey>);

impl Zeroize for RustCryptoKeySlot {
    fn zeroize(&mut self) {
        // The key wipes itself when dropped
        self.0 = None;
    }
}

// The key wipes itself when dropped
impl ZeroizeOnDrop for RustCryptoKeySlot {}

/// The expanded key of [`RustCryptoMlKem768`], which borrows the decoded decapsulation key from
/// its slot.
pub struct RustCryptoExpandedKey<'a>(&'a ml_kem_768::DecapsulationKey);

/// The checked key of [`RustCryptoMlKem768`], the decoded encapsulation key.
#[derive(Clone, Debug)]
pub struct RustCryptoCheckedKey(ml_kem_768::EncapsulationKey);

impl MlKem768 for RustCryptoMlKem768 {
    type KeySlot = RustCryptoKeySlot;
    type ExpandedKey<'a> = RustCryptoExpandedKey<'a>;
    type CheckedKey<'k> = RustCryptoCheckedKey;

    const EMPTY_SLOT: RustCryptoKeySlot = RustCryptoKeySlot(None);

    fn encapsulation_key(&mut self, seed: &mut [u8; 64], out: &mut [u8; 1184]) {
        let key = ml_kem_768::DecapsulationKey::from_seed((*seed).into());
        *out = key.encapsulation_key().to_bytes().into();
    }

    fn expand<'a>(
        &mut self,
        slot: &'a mut RustCryptoKeySlot,
        seed: &mut [u8; 64],
        own: &'a [u8; 1184],
    ) -> Result<RustCryptoExpandedKey<'a>, KeyMismatch> {
        let key = slot
            .0
            .insert(ml_kem_768::DecapsulationKey::from_seed((*seed).into()));
        if key.encapsulation_key().to_bytes().as_slice() != own {
            return Err(KeyMismatch);
        }
        Ok(RustCryptoExpandedKey(key))
    }

    fn check(&mut self, key: &[u8; 1184]) -> Result<RustCryptoCheckedKey, InvalidEncapsulationKey> {
        ml_kem_768::EncapsulationKey::new(key.into())
            .map(RustCryptoCheckedKey)
            .map_err(|_| InvalidEncapsulationKey)
    }

    fn encapsulate(
        &mut self,
        peer: &RustCryptoCheckedKey,
        m: &[u8; 32],
        ciphertext: &mut [u8; 1088],
    ) -> MlKemSharedSecret {
        // Wiped whole, since taking the tuple apart can leave a copy of the shared secret
        let pair = Zeroizing::new(peer.0.encapsulate_deterministic(m.into()));
        ciphertext.copy_from_slice(&pair.0);
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(&pair.1);
        MlKemSharedSecret::new(*secret)
    }

    fn decapsulate(
        &mut self,
        key: &RustCryptoExpandedKey<'_>,
        ciphertext: &[u8; 1088],
    ) -> MlKemSharedSecret {
        let shared = Zeroizing::new(key.0.decapsulate(ciphertext.into()));
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(&shared);
        MlKemSharedSecret::new(*secret)
    }
}
