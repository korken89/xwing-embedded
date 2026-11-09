//! Links the X-Wing operations that features select, or none, and prints the size of `.text`,
//! for `text-size.sh` to measure the code size of each operation. The `rustcrypto` feature
//! selects the RustCrypto ML-KEM-768 instead of `mlkem-otf`, and `cortex-m` selects
//! `CortexMX25519` instead of `DalekX25519`. The `x25519` feature links one X25519 alone.
#![no_std]
#![no_main]

#[cfg(feature = "encapsulate")]
use core::convert::Infallible;
use core::hint::black_box;

use cortex_m_rt::entry;
#[cfg(feature = "encapsulate")]
use rand_core::{TryCryptoRng, TryRng, utils};
use semihosting::{println, process};
use xwing_embedded::{
    Ciphertext, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, ExpandedKeySlot, XWing,
};

#[cfg(not(feature = "rustcrypto"))]
type MlKem = xwing_embedded::OtfMlKem768;
#[cfg(feature = "rustcrypto")]
type MlKem = xwing_embedded::RustCryptoMlKem768;
#[cfg(not(feature = "cortex-m"))]
type X25519 = xwing_embedded::DalekX25519;
#[cfg(feature = "cortex-m")]
type X25519 = xwing_embedded::CortexMX25519;

unsafe extern "C" {
    static __stext: u32;
    static __etext: u32;
}

/// Returns bytes the compiler cannot predict.
#[cfg(feature = "encapsulate")]
struct OpaqueRng;

#[cfg(feature = "encapsulate")]
impl TryRng for OpaqueRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(black_box(0));
        Ok(())
    }
}

#[cfg(feature = "encapsulate")]
impl TryCryptoRng for OpaqueRng {}

#[entry]
fn main() -> ! {
    let kem = &mut XWing::<MlKem, X25519>::default();
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut black_box([0; 32]));
    let mut key_slot = ExpandedKeySlot::<MlKem>::new();
    let mut public = EncapsulationKey::from(black_box([0; 1216]));
    let mut ciphertext = Ciphertext::from(black_box([0; 1120]));
    #[cfg(feature = "encapsulation-key")]
    kem.encapsulation_key(secret_key, &mut public);
    #[cfg(feature = "expand")]
    black_box(kem.expand(&mut key_slot, secret_key, &public).is_ok());
    #[cfg(feature = "check")]
    black_box(kem.check(&public).is_ok());
    #[cfg(feature = "encapsulate")]
    if let Ok(peer) = kem.check(&public) {
        black_box(kem.encapsulate(&mut OpaqueRng, &peer, &mut ciphertext));
    }
    #[cfg(feature = "decapsulate")]
    if let Ok(key) = kem.expand(&mut key_slot, secret_key, &public) {
        black_box(kem.decapsulate(&key, &ciphertext));
    }
    #[cfg(feature = "x25519")]
    {
        use xwing_embedded::{X25519 as _, X25519PublicKey, X25519SecretKey};
        let shared = kem.x25519.shared_secret(
            &X25519SecretKey::new(black_box([0x77; 32])),
            black_box(&X25519PublicKey::BASE_POINT),
        );
        black_box(shared.expose_secret());
    }
    black_box((kem, secret_key, &mut key_slot, &mut public, &mut ciphertext));
    let text = (&raw const __etext).addr() - (&raw const __stext).addr();
    println!("{text}");
    process::exit(0)
}
