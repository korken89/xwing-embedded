//! ML-KEM-768 from the `mlkem-otf` crate.

use crate::{InvalidEncapsulationKey, KeyMismatch, MlKem768, MlKemSharedSecret};
use mlkem_otf::{BoundKey, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, Randomness};

/// ML-KEM-768 in software with a small stack, from the `mlkem-otf` crate. It streams the matrix
/// and the secret vector instead of keeping them, so its key slot keeps the 64-byte seed and both
/// keys borrow the encapsulation key.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OtfMlKem768;

impl MlKem768 for OtfMlKem768 {
    type KeySlot = DecapsulationKeySlot;
    type ExpandedKey<'a> = BoundKey<'a>;
    type CheckedKey<'k> = EncapsulationKey<'k>;

    const EMPTY_SLOT: DecapsulationKeySlot = DecapsulationKeySlot::new();

    fn encapsulation_key(&mut self, seed: &mut [u8; 64], out: &mut [u8; 1184]) {
        let mut slot = DecapsulationKeySlot::new();
        DecapsulationKey::from_seed(&mut slot, seed).encapsulation_key(out);
    }

    fn expand<'a>(
        &mut self,
        slot: &'a mut DecapsulationKeySlot,
        seed: &mut [u8; 64],
        own: &'a [u8; 1184],
    ) -> Result<BoundKey<'a>, KeyMismatch> {
        DecapsulationKey::from_seed(slot, seed)
            .bind(own)
            .map_err(|_| KeyMismatch)
    }

    fn check<'k>(
        &mut self,
        key: &'k [u8; 1184],
    ) -> Result<EncapsulationKey<'k>, InvalidEncapsulationKey> {
        EncapsulationKey::new(key).map_err(|_| InvalidEncapsulationKey)
    }

    fn encapsulate(
        &mut self,
        peer: &EncapsulationKey<'_>,
        m: &[u8; 32],
        ciphertext: &mut [u8; 1088],
    ) -> MlKemSharedSecret {
        let secret = peer.encapsulate_deterministic(&Randomness::from(*m), ciphertext);
        MlKemSharedSecret::new(*secret.expose_secret())
    }

    fn decapsulate(&mut self, key: &BoundKey<'_>, ciphertext: &[u8; 1088]) -> MlKemSharedSecret {
        MlKemSharedSecret::new(*key.decapsulate(ciphertext).expose_secret())
    }
}
