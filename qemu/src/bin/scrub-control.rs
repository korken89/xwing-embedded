//! Positive control of the `DalekX25519` scrub. Without it, the residue check finds the result
//! of its ladder. A binary of its own, so that the other binaries call `curve25519-dalek` only
//! through `DalekX25519`, as an application does.
#![no_std]
#![no_main]

use core::hint::black_box;

use cortex_m_rt::entry;
use curve25519_dalek::MontgomeryPoint;
use measure::{Leaks, clamp, run};
use semihosting::{println, process};

/// The ladder of `DalekX25519` without the scrub.
#[inline(never)]
fn unscrubbed(secret: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let scalar = clamp(secret);
    let bits = (0..255).rev().map(|i| (scalar[i / 8] >> (i % 8)) & 1 == 1);
    MontgomeryPoint(*peer).mul_bits_be(bits).0
}

#[entry]
fn main() -> ! {
    measure::init();
    // RFC 7748 section 6.1, Alice's secret and Bob's public key
    let secret = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let peer = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let shared = unscrubbed(&secret, &peer);
    let leaks = Leaks {
        copies: &[],
        ratios: &[("the result", &shared)],
    };
    let (_, _, left) = run(&leaks, || unscrubbed(black_box(&secret), black_box(&peer)));
    assert!(left.is_some(), "no result without the scrub");
    println!(
        "DalekX25519 without the scrub on a {}: the residue check finds its result",
        env!("CORE")
    );
    process::exit(0)
}
