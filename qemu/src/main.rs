//! Peak stack and instruction count of X-Wing on a Cortex-M33, with draft-11 test vector 1 and
//! each ML-KEM-768 and X25519 backend, and the tests of `CortexMX25519`. Fails if an operation
//! leaves a secret on the stack, also once a key loaded or expanded into a slot on its stack is
//! dropped, or if decapsulation with `mlkem-otf` takes another number of instructions for a
//! modified ciphertext. Run with `make test-qemu`, which builds the QEMU plugin.
#![no_std]
#![no_main]

use core::hint::black_box;

use cortex_m_rt::entry;
use measure::{
    CT, ESEED, EXPANDED, FixedRng, K_BAR, Leaks, R, SIGMA, SK, SS, Secrets, Stub, checked, clamp,
    measure, print_sizes, run, search_controls, second_point,
    x25519_cortex_m::{self, Clamped},
};
use semihosting::{println, process};
use xwing_embedded::{
    CheckedKey, Ciphertext, CortexMX25519, DalekX25519, DecapsulationKey, DecapsulationKeySlot,
    EncapsulationKey, ExpandedKeySlot, InvalidEncapsulationKey, KeyMismatch, MlKem768,
    MlKemSharedSecret, OtfMlKem768, RustCryptoMlKem768, X25519, X25519SecretKey, XWing,
};

/// What each operation must not leave on the stack.
struct Residue<'a> {
    /// After loading and expanding the key, also into a dropped slot, and after every operation.
    long_term: &'a [&'a Secrets<'a>],
    encapsulate: Leaks<'a>,
    decapsulate: Leaks<'a>,
}

#[entry]
fn main() -> ! {
    measure::init();
    println!("X-Wing on a Cortex-M33, draft-11 vector 1:");
    println!("  {:<44} {:>7} {:>11}", "", "stack", "instr");
    rows();
    print_sizes();
    process::exit(0)
}

/// The rows and tests of this crate with each backend.
fn rows() {
    let (ss_m, ss_x, combined) = component_secrets();
    let (d_z, sk_x) = EXPANDED.split_at(64);
    let (m, ek_x) = ESEED.split_at(32);
    let (sk_x_clamped, ek_x_clamped) = (clamp(sk_x), clamp(ek_x));
    // `sk_X` has 32 bytes
    let pk_x = DalekX25519.public_key(&X25519SecretKey::new(sk_x.try_into().unwrap()));
    let encapsulate_point = second_point(ek_x, pk_x.as_ref(), &ss_x);
    let decapsulate_point = second_point(sk_x, &CT[1088..], &ss_x);
    controls::<OtfMlKem768>(m, &ss_m);
    controls::<RustCryptoMlKem768>(m, &ss_m);
    search_controls(&ss_x);
    load();

    let sk = ("sk", &SK[..]);
    let (d, z) = d_z.split_at(32);
    let (seed, d, z) = (("d || z", d_z), ("d", d), ("z", z));
    let sigma = ("sigma", &SIGMA[..]);
    // The assembly keeps a copy of the scalar with only bits 0 to 2 and 254 clamped
    let (asm_sk_x, asm_ek_x) = (Clamped::new(sk_x), Clamped::new(ek_x));
    let c = asm_sk_x.pieces("clamped sk_X");
    let e = asm_ek_x.pieces("clamped ek_X");
    let sk_x = ("sk_X", sk_x);
    let ek_x = ("ek_X", ek_x);
    let sk_x_clamped = ("clamped sk_X", &sk_x_clamped[..]);
    let ek_x_clamped = ("clamped ek_X", &ek_x_clamped[..]);
    let (m, r, k_bar) = (("m", m), ("r", &R[..]), ("K_bar", &K_BAR[..]));
    let ss_m = ("ss_M", &ss_m[..]);
    let (combined, ss) = (("ss_M || ss_X", &combined[..]), ("ss", &SS[..]));
    let encapsulate_ratios = &[("ss_X", &ss_x), ("u([k + 1] pk_X)", &encapsulate_point)];
    let decapsulate_ratios = &[("ss_X", &ss_x), ("u([k + 1] ct_X)", &decapsulate_point)];
    let ss_x = ("ss_X", &ss_x[..]);

    let otf_long_term = &[sk, seed, d, z, sigma, sk_x, sk_x_clamped];
    let encapsulate = &[m, r, ek_x, ek_x_clamped, ss_m, ss_x, combined, ss];
    let otf_decapsulate = &[m, r, k_bar, ss_m, ss_x, combined, ss];
    // The RustCrypto `ml-kem` crate leaves `sigma`, and copies of the decoded key with `d` and
    // `z`, on the stack at some opt levels, and `m`, `r` and `ss_M` of decapsulation.
    let ml_kem_long_term = &[sk, seed, sk_x, sk_x_clamped];
    let ml_kem_decapsulate = &[k_bar, ss_x, combined, ss];

    let otf_dalek = Residue {
        long_term: &[otf_long_term],
        encapsulate: Leaks {
            copies: &[encapsulate, otf_long_term],
            ratios: encapsulate_ratios,
        },
        decapsulate: Leaks {
            copies: &[otf_decapsulate, otf_long_term],
            ratios: decapsulate_ratios,
        },
    };
    let ml_kem_dalek = Residue {
        long_term: &[ml_kem_long_term],
        encapsulate: Leaks {
            copies: &[encapsulate, ml_kem_long_term],
            ratios: encapsulate_ratios,
        },
        decapsulate: Leaks {
            copies: &[ml_kem_decapsulate, ml_kem_long_term],
            ratios: decapsulate_ratios,
        },
    };
    let otf_cortex_m = Residue {
        long_term: &[otf_long_term, &c],
        encapsulate: Leaks {
            copies: &[encapsulate, otf_long_term, &c, &e],
            ratios: encapsulate_ratios,
        },
        decapsulate: Leaks {
            copies: &[otf_decapsulate, otf_long_term, &c],
            ratios: decapsulate_ratios,
        },
    };
    let ml_kem_cortex_m = Residue {
        long_term: &[ml_kem_long_term, &c],
        encapsulate: Leaks {
            copies: &[encapsulate, ml_kem_long_term, &c, &e],
            ratios: encapsulate_ratios,
        },
        decapsulate: Leaks {
            copies: &[ml_kem_decapsulate, ml_kem_long_term, &c],
            ratios: decapsulate_ratios,
        },
    };
    let sizes_otf = backend::<OtfMlKem768, DalekX25519>("mlkem-otf/dalek", &otf_dalek);
    backend::<OtfMlKem768, CortexMX25519>("mlkem-otf/cortex-m", &otf_cortex_m);
    let sizes_ml_kem = backend::<RustCryptoMlKem768, DalekX25519>("ml-kem/dalek", &ml_kem_dalek);
    backend::<RustCryptoMlKem768, CortexMX25519>("ml-kem/cortex-m", &ml_kem_cortex_m);
    constant_time_decapsulate::<OtfMlKem768, DalekX25519>("mlkem-otf/dalek");
    constant_time_decapsulate::<OtfMlKem768, CortexMX25519>("mlkem-otf/cortex-m");
    stub_residue();
    negative_control();
    x25519_cortex_m::rows();

    println!();
    let sizes = [("mlkem-otf", sizes_otf), ("ml-kem", sizes_ml_kem)];
    for (backend, (slot, expanded, checked)) in sizes {
        println!("  {backend:<18} {:<25} {slot:>7}", "ExpandedKeySlot size");
        println!("  {backend:<18} {:<25} {expanded:>7}", "ExpandedKey size");
        println!("  {backend:<18} {:<25} {checked:>7}", "CheckedKey size");
    }
}

/// Checks that loading the seed wipes the caller's copy, and that a key loaded or generated
/// into a slot on the stack is gone once the slot is dropped.
fn load() {
    let sk: [&Secrets; 1] = [&[("sk", &SK)]];
    let sk = Leaks::copies(&sk);
    let mut slot = DecapsulationKeySlot::new();
    let mut seed = SK;
    let (slot, stored) = (&mut slot, &mut seed);
    checked("x-wing", "from_seed", &sk, move || {
        DecapsulationKey::from_seed(slot, black_box(stored))
    });
    assert!(
        seed == [0; 32],
        "from_seed left the seed in the caller's buffer"
    );
    checked("x-wing", "from_seed into a dropped slot", &sk, || {
        let mut slot = DecapsulationKeySlot::new();
        let mut seed = SK;
        black_box(DecapsulationKey::from_seed(&mut slot, &mut seed));
    });
    checked("x-wing", "generate into a dropped slot", &sk, || {
        let mut slot = DecapsulationKeySlot::new();
        black_box(DecapsulationKey::generate(&mut slot, &mut FixedRng(&SK)));
    });
}

/// Measures every operation with the ML-KEM-768 `M` and the X25519 `X` and returns the sizes of
/// the expanded key slot, the expanded key and the checked key. Also checks that a key expanded
/// into a slot on the stack is gone once the slot is dropped.
fn backend<M: MlKem768 + Default, X: X25519 + Default>(
    name: &str,
    residue: &Residue,
) -> (usize, usize, usize) {
    let kem = &mut XWing::<M, X>::default();
    let long_term = Leaks::copies(residue.long_term);
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut SK.clone());
    let mut public = EncapsulationKey::from([0; 1216]);
    measure(name, "encapsulation_key", &long_term, || {
        kem.encapsulation_key(black_box(secret_key), &mut public)
    });
    let mut key_slot = ExpandedKeySlot::<M>::new();
    let (k, slot, own) = (&mut *kem, &mut key_slot, &public);
    let key = measure(name, "expand", &long_term, move || {
        // The encapsulation key is the one of the decapsulation key
        k.expand(slot, black_box(secret_key), black_box(own))
            .unwrap()
    });
    checked(name, "expand into a dropped slot", &long_term, || {
        let mut slot = ExpandedKeySlot::<M>::new();
        // The encapsulation key is the one of the decapsulation key
        black_box(
            kem.expand(&mut slot, black_box(secret_key), black_box(&public))
                .unwrap(),
        );
    });
    let peer: CheckedKey<M> = measure(name, "check", &long_term, || {
        // The encapsulation key is valid
        kem.check(black_box(&public)).unwrap()
    });
    let mut ciphertext = Ciphertext::from([0; 1120]);
    let secret = measure(name, "encapsulate", &residue.encapsulate, || {
        kem.encapsulate(&mut FixedRng(&ESEED), black_box(&peer), &mut ciphertext)
    });
    assert!(ciphertext.as_ref() == &CT && secret.expose_secret() == &SS);
    let secret = measure(name, "decapsulate", &residue.decapsulate, || {
        kem.decapsulate(black_box(&key), black_box(&ciphertext))
    });
    assert!(secret.expose_secret() == &SS);
    (
        size_of::<ExpandedKeySlot<M>>(),
        size_of_val(&key),
        size_of_val(&peer),
    )
}

/// Checks that decapsulation with the ML-KEM-768 `M` and the X25519 `X` takes the same number of
/// instructions for the valid ciphertext and for ones with `ct_M` or `ct_X` tampered.
fn constant_time_decapsulate<M: MlKem768 + Default, X: X25519 + Default>(name: &str) {
    let kem = &mut XWing::<M, X>::default();
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut SK.clone());
    let mut public = EncapsulationKey::from([0; 1216]);
    kem.encapsulation_key(secret_key, &mut public);
    let mut key_slot = ExpandedKeySlot::new();
    // The encapsulation key is the one of the decapsulation key
    let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
    // Bits of `u` and `v` in `ct_M`, every byte of `ct_M`, and bits of `ct_X`, including bit 255
    let tampered = [
        (0..1, 0x01),
        (1087..1088, 0x10),
        (0..1088, 0xff),
        (1088..1089, 0x01),
        (1119..1120, 0x80),
    ];
    let mut count = None;
    for (range, bits) in [(0..0, 0)].into_iter().chain(tampered) {
        let mut ciphertext = Ciphertext::from(CT);
        for byte in &mut ciphertext.as_mut()[range.clone()] {
            *byte ^= bits;
        }
        let (secret, usage, _) = run(&Leaks::default(), || {
            kem.decapsulate(black_box(&key), black_box(&ciphertext))
        });
        assert!((secret.expose_secret() == &SS) == range.is_empty());
        let n = usage.instructions;
        assert!(
            *count.get_or_insert(n) == n,
            "{name} decapsulate: {n} instructions, not {count:?}"
        );
    }
    println!(
        "  {name:<18} decapsulate, valid and tampered ct_M and ct_X: {} instructions each",
        count.unwrap_or(0)
    );
}

/// Checks that the search finds nothing of a value unrelated to the operation, after the
/// decapsulation with the most stack.
fn negative_control() {
    let unrelated = [0x3c; 32];
    let kem = &mut XWing::<RustCryptoMlKem768, DalekX25519>::default();
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut SK.clone());
    let mut public = EncapsulationKey::from([0; 1216]);
    kem.encapsulation_key(secret_key, &mut public);
    let mut key_slot = ExpandedKeySlot::new();
    // The encapsulation key is the one of the decapsulation key
    let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
    let ciphertext = Ciphertext::from(CT);
    let leaks = Leaks {
        copies: &[&[("an unrelated value", &unrelated)]],
        ratios: &[("an unrelated value", &unrelated)],
    };
    let (_, _, left) = run(&leaks, || {
        kem.decapsulate(black_box(&key), black_box(&ciphertext))
    });
    assert!(left.is_none(), "the residue check found an unrelated value");
}

/// `ss_M`, `ss_X` and `ss_M || ss_X` of the vector. Only the combiner holds the two next to each
/// other. The next measurement paints over what this leaves on the stack.
fn component_secrets() -> ([u8; 32], [u8; 32], [u8; 64]) {
    let mut public = EncapsulationKey::from([0; 1216]);
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut SK.clone());
    XWing::<OtfMlKem768, DalekX25519>::default().encapsulation_key(secret_key, &mut public);
    let (m, ephemeral) = ESEED.split_at(32);
    let (pk_m, pk_x) = public.as_ref().split_at(1184);
    let ml_kem = &mut OtfMlKem768;
    // The vector's encapsulation key is valid
    let peer = ml_kem.check(pk_m.try_into().unwrap()).unwrap();
    let mut ct_m = [0; 1088];
    // `ESEED` has 64 bytes
    let ss_m = ml_kem.encapsulate(&peer, m.try_into().unwrap(), &mut ct_m);
    // `ESEED` has 64 bytes and `pk_x` 32
    let ss_x = DalekX25519.shared_secret(
        &X25519SecretKey::new(ephemeral.try_into().unwrap()),
        &<[u8; 32]>::try_from(pk_x).unwrap().into(),
    );
    let mut combined = [0; 64];
    combined[..32].copy_from_slice(ss_m.expose_secret());
    combined[32..].copy_from_slice(ss_x.expose_secret());
    (*ss_m.expose_secret(), *ss_x.expose_secret(), combined)
}

/// Leaves `secret` on the stack at an aligned and at an unaligned address, 4 KiB deep so that
/// the rest of the X-Wing operation does not overwrite it.
#[inline(never)]
fn plant(secret: &[u8; 32]) {
    let mut copy = [0; 4096];
    copy[..32].copy_from_slice(black_box(secret));
    copy[35..67].copy_from_slice(black_box(secret));
    black_box(&mut copy);
}

/// The ML-KEM-768 `M`, which leaves `m` after encapsulation and the shared secret after
/// decapsulation on the stack, for the positive controls of the residue checks.
#[derive(Default)]
struct Planting<M>(M);

impl<M: MlKem768> MlKem768 for Planting<M> {
    type KeySlot = M::KeySlot;
    type ExpandedKey<'a> = M::ExpandedKey<'a>;
    type CheckedKey<'k> = M::CheckedKey<'k>;

    const EMPTY_SLOT: M::KeySlot = M::EMPTY_SLOT;

    fn encapsulation_key(&mut self, seed: &mut [u8; 64], out: &mut [u8; 1184]) {
        self.0.encapsulation_key(seed, out);
    }

    fn expand<'a>(
        &mut self,
        slot: &'a mut M::KeySlot,
        seed: &mut [u8; 64],
        own: &'a [u8; 1184],
    ) -> Result<M::ExpandedKey<'a>, KeyMismatch> {
        self.0.expand(slot, seed, own)
    }

    fn check<'k>(
        &mut self,
        key: &'k [u8; 1184],
    ) -> Result<M::CheckedKey<'k>, InvalidEncapsulationKey> {
        self.0.check(key)
    }

    fn encapsulate(
        &mut self,
        peer: &M::CheckedKey<'_>,
        m: &[u8; 32],
        ciphertext: &mut [u8; 1088],
    ) -> MlKemSharedSecret {
        let secret = self.0.encapsulate(peer, m, ciphertext);
        plant(m);
        secret
    }

    fn decapsulate(
        &mut self,
        key: &M::ExpandedKey<'_>,
        ciphertext: &[u8; 1088],
    ) -> MlKemSharedSecret {
        let secret = self.0.decapsulate(key, ciphertext);
        plant(secret.expose_secret());
        secret
    }
}

/// Checks that the residue checks find `m` and `ss_M` when the ML-KEM-768 `M` leaves them on the
/// stack in X-Wing encapsulation and decapsulation.
fn controls<M: MlKem768 + Default>(m: &[u8], ss_m: &[u8; 32]) {
    let kem = &mut XWing::<Planting<M>, DalekX25519>::default();
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut SK.clone());
    let mut public = EncapsulationKey::from([0; 1216]);
    kem.encapsulation_key(secret_key, &mut public);
    let mut key_slot = ExpandedKeySlot::new();
    // The encapsulation key is the one of the decapsulation key
    let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
    // The encapsulation key is valid
    let peer = kem.check(&public).unwrap();
    let mut ciphertext = Ciphertext::from([0; 1120]);
    let (_, _, left) = run(&Leaks::copies(&[&[("m", m)]]), || {
        kem.encapsulate(&mut FixedRng(&ESEED), black_box(&peer), &mut ciphertext)
    });
    assert!(left.is_some(), "the residue check missed m");
    let (_, _, left) = run(&Leaks::copies(&[&[("ss_M", ss_m)]]), || {
        kem.decapsulate(black_box(&key), black_box(&ciphertext))
    });
    assert!(left.is_some(), "the residue check missed ss_M");
}

/// Checks that the X-Wing code itself leaves no key or seed on the stack, with [`Stub`] components.
fn stub_residue() {
    let kem = &mut XWing {
        ml_kem: Stub,
        x25519: Stub,
    };
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut SK.clone());
    let (d_z, sk_x) = EXPANDED.split_at(64);
    let sk_x_clamped = clamp(sk_x);
    let seed: &Secrets = &[
        ("sk", &SK[..]),
        ("d || z", d_z),
        ("sk_X", sk_x),
        ("clamped sk_X", &sk_x_clamped[..]),
    ];
    let long_term = [seed];
    let long_term = Leaks::copies(&long_term);
    let mut public = EncapsulationKey::from([0; 1216]);
    checked("stub", "encapsulation_key", &long_term, || {
        kem.encapsulation_key(black_box(secret_key), &mut public)
    });
    let mut key_slot = ExpandedKeySlot::new();
    let (k, slot, own) = (&mut *kem, &mut key_slot, &public);
    let (key, _) = checked("stub", "expand", &long_term, move || {
        // The stub accepts every encapsulation key
        k.expand(slot, black_box(secret_key), black_box(own))
            .unwrap()
    });
    checked("stub", "expand into a dropped slot", &long_term, || {
        let mut slot = ExpandedKeySlot::new();
        // The stub accepts every encapsulation key
        black_box(
            kem.expand(&mut slot, black_box(secret_key), black_box(&public))
                .unwrap(),
        );
    });
    // The stub accepts every encapsulation key
    let peer = kem.check(&public).unwrap();
    let (m, ek_x) = ESEED.split_at(32);
    let ek_x_clamped = clamp(ek_x);
    let ephemeral: &Secrets = &[
        ("m", m),
        ("ek_X", ek_x),
        ("clamped ek_X", &ek_x_clamped[..]),
    ];
    let mut ciphertext = Ciphertext::from([0; 1120]);
    checked(
        "stub",
        "encapsulate",
        &Leaks::copies(&[ephemeral, seed]),
        || kem.encapsulate(&mut FixedRng(&ESEED), black_box(&peer), &mut ciphertext),
    );
    checked("stub", "decapsulate", &long_term, || {
        kem.decapsulate(black_box(&key), black_box(&ciphertext))
    });
}
