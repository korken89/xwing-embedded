//! X25519 from the Montgomery ladder of `curve25519-dalek`.

use core::hint::black_box;

use curve25519_dalek::MontgomeryPoint;
use zeroize::{Zeroize, Zeroizing};

use crate::{X25519, X25519PublicKey, X25519SecretKey, X25519SharedSecret};

/// Bytes of stack that [`scrub`] zeroes. [`ladder`] uses up to 2,000 bytes on ARMv7E-M and
/// ARMv8-M from opt-level 1 up, so 2,560 has about 25 % margin. At opt-level 0, as in the default
/// dev profile, it uses 3,600 bytes, so builds with debug assertions zero 4,096.
const SCRUB: usize = if cfg!(debug_assertions) { 4096 } else { 2560 };

/// X25519 in software, from `curve25519-dalek`, the crate under `x25519-dalek`.
///
/// `curve25519-dalek` leaves its ladder state on the stack, so after each call this zeroes 2,560
/// bytes of stack below its frame, or 4,096 bytes with debug assertions. On ARMv7E-M and ARMv8-M
/// that covers the ladder from opt-level 1 up, and at opt-level 0 with debug assertions. With its
/// frame it uses 2,664 bytes of stack on a Cortex-M33 at opt-level s. On other targets and
/// opt-levels the ladder can use more, and a part of it stays unwiped.
///
/// The exception frame of an interrupt during the call is inside the zeroed stack. The interrupt
/// handler can push registers that hold secret intermediates below the zeroed stack, where they
/// stay, so mask interrupts around the call or run it at the lowest priority if that matters.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DalekX25519;

impl X25519 for DalekX25519 {
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        peer: &X25519PublicKey,
    ) -> X25519SharedSecret {
        let mut shared = Zeroizing::new([0; 32]);
        ladder(&mut shared, secret, peer);
        scrub();
        X25519SharedSecret::new(*shared)
    }
}

/// Writes `X25519(secret, peer)` to `out`. Not inlined, so its frame is below the caller's, where
/// [`scrub`] zeroes it.
#[inline(never)]
fn ladder(out: &mut [u8; 32], secret: &X25519SecretKey, peer: &X25519PublicKey) {
    // Clamped in place and read by reference, since `mul_clamped` leaves an unwiped copy of the
    // clamped scalar
    let mut scalar = Zeroizing::new([0; 32]);
    scalar.copy_from_slice(secret.expose_secret());
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    // Bits 254 to 0, most significant first, as in `mul_clamped`
    let bits = (0..255).rev().map(|i| (scalar[i / 8] >> (i % 8)) & 1 == 1);
    *out = MontgomeryPoint((*peer).into()).mul_bits_be(bits).0;
}

/// Zeroes the stack below the caller's frame, which [`ladder`] used. `curve25519-dalek` leaves
/// the ladder state and the result there unwiped.
#[inline(never)]
fn scrub() {
    let mut stack = [0; SCRUB / 4];
    stack.zeroize();
    black_box(&mut stack);
}
