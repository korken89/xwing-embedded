//! The tests and measurements of `CortexMX25519` alone, for a Cortex-M4. The `measure` binary
//! runs the same on a Cortex-M33.
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use measure::{print_sizes, search_controls, x25519_cortex_m};
use semihosting::{println, process};

#[entry]
fn main() -> ! {
    measure::init();
    search_controls(&[0x42; 32]);
    println!("CortexMX25519 on a Cortex-M4:");
    println!("  {:<44} {:>7} {:>11}", "", "stack", "instr");
    x25519_cortex_m::rows();
    print_sizes();
    process::exit(0)
}
