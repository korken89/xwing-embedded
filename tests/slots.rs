//! Keys are filled in place into slots, the caller's seed is wiped, a refilled slot holds the new
//! key and an RNG error is returned.

use chacha20::ChaCha20Rng;
use rand_core::{SeedableRng, TryCryptoRng, TryRng};
use xwing_embedded::{
    Ciphertext, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, ExpandedKeySlot,
    SoftwareXWing,
};

/// An RNG that always fails.
struct FailingRng;

impl TryRng for FailingRng {
    type Error = core::fmt::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(core::fmt::Error)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(core::fmt::Error)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(core::fmt::Error)
    }
}

impl TryCryptoRng for FailingRng {}

/// The encapsulation key of `key`.
fn encapsulation_key_of(kem: &mut SoftwareXWing, key: &DecapsulationKey) -> EncapsulationKey {
    let mut public = EncapsulationKey::from([0; 1216]);
    kem.encapsulation_key(key, &mut public);
    public
}

#[test]
fn from_seed_wipes_the_seed() {
    let mut seed = [9; 32];
    DecapsulationKey::from_seed(&mut DecapsulationKeySlot::new(), &mut seed);
    assert_eq!(seed, [0; 32]);
}

#[test]
fn refilled_slots_hold_the_new_key() {
    let kem = &mut SoftwareXWing::default();
    let mut slot = DecapsulationKeySlot::new();
    let first_public =
        encapsulation_key_of(kem, DecapsulationKey::from_seed(&mut slot, &mut [1; 32]));
    let second = DecapsulationKey::generate(&mut slot, &mut ChaCha20Rng::from_seed([2; 32]));
    let second_public = encapsulation_key_of(kem, second);
    assert_ne!(first_public, second_public);

    let rng = &mut ChaCha20Rng::from_seed([3; 32]);
    let mut ciphertext = Ciphertext::from([0; 1120]);
    let peer = kem.check(&second_public).unwrap();
    let sent = kem.encapsulate(rng, &peer, &mut ciphertext);

    let mut first_slot = DecapsulationKeySlot::new();
    let first = DecapsulationKey::from_seed(&mut first_slot, &mut [1; 32]);
    let mut key_slot = ExpandedKeySlot::new();
    let key = kem.expand(&mut key_slot, first, &first_public).unwrap();
    assert_ne!(
        kem.decapsulate(&key, &ciphertext).expose_secret(),
        sent.expose_secret()
    );
    let key = kem.expand(&mut key_slot, second, &second_public).unwrap();
    assert_eq!(
        kem.decapsulate(&key, &ciphertext).expose_secret(),
        sent.expose_secret()
    );
}

#[test]
fn returns_the_rng_error() {
    let kem = &mut SoftwareXWing::default();
    let mut slot = DecapsulationKeySlot::new();
    assert!(DecapsulationKey::try_generate(&mut slot, &mut FailingRng).is_err());

    let key = DecapsulationKey::from_seed(&mut slot, &mut [4; 32]);
    let public = encapsulation_key_of(kem, key);
    let peer = kem.check(&public).unwrap();
    let mut ciphertext = Ciphertext::from([0x5a; 1120]);
    assert!(
        kem.try_encapsulate(&mut FailingRng, &peer, &mut ciphertext)
            .is_err()
    );
    assert_eq!(ciphertext, Ciphertext::from([0x5a; 1120]));
}
