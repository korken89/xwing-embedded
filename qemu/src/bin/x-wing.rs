//! Peak stack and instruction count of the RustCrypto `x-wing` crate on a Cortex-M33, with
//! draft-11 test vector 1, for comparison.
#![no_std]
#![no_main]

use core::hint::black_box;

use cortex_m_rt::entry;
use measure::{CT, ESEED, Leaks, SK, SS, measure, print_sizes};
use semihosting::{println, process};
use x_wing::{Decapsulate, Decapsulator, KeyExport, TryKeyInit};

#[entry]
fn main() -> ! {
    measure::init();
    println!("The RustCrypto x-wing crate on a Cortex-M33, draft-11 vector 1:");
    println!("  {:<44} {:>7} {:>11}", "", "stack", "instr");
    let key = measure(
        "x-wing",
        "DecapsulationKey::from",
        &Leaks::default(),
        || x_wing::DecapsulationKey::from(*black_box(&SK)),
    );
    let bytes = key.encapsulation_key().to_bytes();
    let peer = measure("x-wing", "EncapsulationKey::new", &Leaks::default(), || {
        x_wing::EncapsulationKey::new(black_box(&bytes)).unwrap()
    });
    let (ciphertext, secret) = measure(
        "x-wing",
        "encapsulate_deterministic",
        &Leaks::default(),
        || black_box(&peer).encapsulate_deterministic(black_box(&ESEED).into()),
    );
    assert!(ciphertext.as_slice() == CT && secret.as_slice() == SS);
    let secret = measure("x-wing", "decapsulate", &Leaks::default(), || {
        black_box(&key).decapsulate(black_box(&ciphertext))
    });
    assert!(secret.as_slice() == SS);
    print_sizes();
    process::exit(0)
}
