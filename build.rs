//! Sets `cortex_m_dsp` when the target runs the `x25519-cortex-m` assembly: ARMv7E-M, or
//! ARMv8-M Mainline with the DSP extension enabled by `-C target-cpu` or `-C target-feature`.

use std::env;

/// The ARMv8-M Mainline cores LLVM builds with the DSP extension.
const DSP_CPUS: &[&str] = &[
    "cortex-m33",
    "cortex-m35p",
    "cortex-m52",
    "cortex-m55",
    "cortex-m85",
    "star-mc1",
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(cortex_m_dsp)");
    let target = env::var("TARGET").unwrap_or_default();
    if target.starts_with("thumbv7em-") || target.starts_with("thumbv8m.main-") && dsp_enabled() {
        println!("cargo::rustc-cfg=cortex_m_dsp");
    }
}

/// Whether the rustc flags enable the DSP extension. rustc does not expose it to `cfg` on
/// stable.
fn dsp_enabled() -> bool {
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let mut flags = flags.split('\x1f');
    let (mut cpu, mut feature) = (false, None);
    while let Some(flag) = flags.next() {
        let codegen = match flag {
            "-C" | "--codegen" => flags.next().unwrap_or_default(),
            _ => flag
                .strip_prefix("-C")
                .or_else(|| flag.strip_prefix("--codegen="))
                .unwrap_or_default(),
        };
        if let Some(name) = codegen.strip_prefix("target-cpu=") {
            cpu = DSP_CPUS.contains(&name);
        } else if let Some(features) = codegen.strip_prefix("target-feature=") {
            for f in features.split(',') {
                match f {
                    "+dsp" => feature = Some(true),
                    "-dsp" => feature = Some(false),
                    _ => {}
                }
            }
        }
    }
    feature.unwrap_or(cpu)
}
