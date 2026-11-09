//! Puts the memory layout of the QEMU machine on the linker path and writes draft-11 test vector
//! 1 to `OUT_DIR`, with its expanded seed and the ML-KEM-768 secrets that the residue checks look
//! for, and the vectors of the `CortexMX25519` tests.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // The mps2-an386 (Cortex-M4) for ARMv7E-M, else the mps2-an505 (Cortex-M33)
    let (memory, core) = if env::var("TARGET").unwrap().starts_with("thumbv7em-") {
        ("memory-an386.x", "Cortex-M4")
    } else {
        ("memory-an505.x", "Cortex-M33")
    };
    println!("cargo:rustc-env=CORE={core}");
    fs::copy(memory, out.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={memory}");

    let vectors = "../tests/data/draft-11.json";
    println!("cargo:rerun-if-changed={vectors}");
    let vectors: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vectors).unwrap()).unwrap();
    for name in ["sk", "eseed", "ct", "ss"] {
        let bytes = hex::decode(vectors[0][name].as_str().unwrap()).unwrap();
        fs::write(out.join(format!("{name}.bin")), bytes).unwrap();
    }

    // `SHAKE256(sk, 96 * 8)`, `d || z || sk_X`
    let sk = hex::decode(vectors[0]["sk"].as_str().unwrap()).unwrap();
    let mut xof = Shake256::default();
    xof.update(&sk);
    let mut expanded = [0; 96];
    xof.finalize_xof().read(&mut expanded);
    fs::write(out.join("expanded.bin"), expanded).unwrap();

    // The seed of the secret vector `sigma` from `G(d || k)` (FIPS 203 Algorithm 13), `r` from
    // `(K, r) = G(m || H(ek))` (Algorithm 17) and the implicit rejection key `J(z || c)` of the
    // valid ciphertext (Algorithm 18).
    let (d, z) = expanded[..64].split_at(32);
    let sigma = Sha3_512::new().chain_update(d).chain_update([3]).finalize();
    fs::write(out.join("sigma.bin"), &sigma[32..]).unwrap();
    let pk = hex::decode(vectors[0]["pk"].as_str().unwrap()).unwrap();
    let eseed = hex::decode(vectors[0]["eseed"].as_str().unwrap()).unwrap();
    let k_r = Sha3_512::new()
        .chain_update(&eseed[..32])
        .chain_update(Sha3_256::digest(&pk[..1184]))
        .finalize();
    fs::write(out.join("r.bin"), &k_r[32..]).unwrap();
    let ct = hex::decode(vectors[0]["ct"].as_str().unwrap()).unwrap();
    let mut k_bar = [0; 32];
    Shake256::default()
        .chain(z)
        .chain(&ct[..1088])
        .finalize_xof_into(&mut k_bar);
    fs::write(out.join("k_bar.bin"), k_bar).unwrap();

    cortex_m_vectors(&out, &vectors);
}

/// Writes the draft-11 vectors as `sk || eseed || ct || ss || pk || sk_X` records and the Wycheproof
/// X25519 vectors as `private || public || shared` records, for the `x25519-cortex-m` tests.
fn cortex_m_vectors(out: &Path, draft: &serde_json::Value) {
    let hex = |v: &serde_json::Value, name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
    let mut records = Vec::new();
    for v in draft.as_array().unwrap() {
        for name in ["sk", "eseed", "ct", "ss", "pk"] {
            records.extend(hex(v, name));
        }
        let mut sk_x = [0; 96];
        Shake256::default()
            .chain(hex(v, "sk"))
            .finalize_xof_into(&mut sk_x);
        records.extend(&sk_x[64..]);
    }
    fs::write(out.join("draft-11.bin"), records).unwrap();

    let wycheproof = "../tests/data/wycheproof-x25519.json";
    println!("cargo:rerun-if-changed={wycheproof}");
    let wycheproof: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(wycheproof).unwrap()).unwrap();
    let mut records = Vec::new();
    for group in wycheproof["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            for name in ["private", "public", "shared"] {
                records.extend(hex(test, name));
            }
        }
    }
    assert_eq!(records.len(), 518 * 96);
    fs::write(out.join("wycheproof-x25519.bin"), records).unwrap();
}
