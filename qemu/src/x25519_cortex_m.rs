//! Rows and tests of the `x25519-cortex-m` X25519: RFC 7748 and Wycheproof vectors, a
//! differential test against `x25519-dalek`, the draft-11 vectors with each ML-KEM-768, the
//! constant-time checks and the stack residue checks of both X25519 with positive controls.

use core::hint::black_box;

use chacha20::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use semihosting::println;
use xwing_embedded::{
    Ciphertext, CortexMX25519, DalekX25519, DecapsulationKey, DecapsulationKeySlot,
    EncapsulationKey, ExpandedKeySlot, MlKem768, OtfMlKem768, RustCryptoMlKem768, X25519,
    X25519PublicKey, X25519SecretKey, X25519SharedSecret, XWing,
};

use crate::{FixedRng, Leaks, Stub, checked, clamp, instructions, measure, run, second_point};

/// Draft-11 vectors as `sk || eseed || ct || ss || pk || sk_X` records.
static DRAFT: [u8; 3 * DRAFT_RECORD] = *include_bytes!(concat!(env!("OUT_DIR"), "/draft-11.bin"));
const DRAFT_RECORD: usize = 32 + 64 + 1120 + 32 + 1216 + 32;

/// A record of [`DRAFT`].
struct Vector {
    sk: &'static [u8; 32],
    eseed: &'static [u8],
    ct: &'static [u8],
    ss: &'static [u8; 32],
    pk: &'static [u8],
    sk_x: &'static [u8; 32],
}

/// The records of [`DRAFT`].
fn vectors() -> impl Iterator<Item = Vector> {
    DRAFT.as_chunks::<DRAFT_RECORD>().0.iter().map(|v| {
        let (sk, v) = v.split_first_chunk().unwrap_or_else(|| unreachable!());
        let (eseed, v) = v.split_at(64);
        let (ct, v) = v.split_at(1120);
        let (ss, v) = v.split_first_chunk().unwrap_or_else(|| unreachable!());
        let (pk, sk_x) = v.split_at(1216);
        let sk_x = sk_x.try_into().unwrap_or_else(|_| unreachable!());
        Vector {
            sk,
            eseed,
            ct,
            ss,
            pk,
            sk_x,
        }
    })
}

/// Wycheproof `x25519_test.json` as `private || public || shared` records.
static WYCHEPROOF: [u8; 518 * 96] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/wycheproof-x25519.bin"));

/// Random inputs of the differential test against `x25519-dalek`.
const DIFFERENTIAL: usize = 64;

unsafe extern "C" {
    /// The assembly without the wrapper, so without the stack wipe.
    fn xwing_embedded_0_1_curve25519_scalarmult(
        result: *mut u8,
        scalar: *const u8,
        point: *const u8,
    );
}

/// The assembly without the stack wipe, for the positive controls of the residue checks.
struct Unwiped;

impl X25519 for Unwiped {
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        peer: &X25519PublicKey,
    ) -> X25519SharedSecret {
        let mut shared = [0; 32];
        // SAFETY: Reads 32 bytes from the scalar and the point and writes 32 bytes to `shared`.
        unsafe {
            xwing_embedded_0_1_curve25519_scalarmult(
                shared.as_mut_ptr(),
                secret.expose_secret().as_ptr(),
                peer.as_ref().as_ptr(),
            )
        };
        X25519SharedSecret::new(shared)
    }
}

/// Decodes 64 hex digits.
const fn h(hex: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let hex = hex.as_bytes();
    assert!(hex.len() == 64);
    let mut out = [0; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

/// The copy of a scalar the assembly keeps on its stack, with bits 0-2 cleared and bit 254 set.
pub struct Clamped([u8; 32]);

impl Clamped {
    /// The copy of `scalar`. Its first 8 bytes differ from the scalar's, so a search for them
    /// does not find the scalar itself.
    pub fn new(scalar: &[u8]) -> Self {
        // Scalars have 32 bytes
        let mut copy: [u8; 32] = scalar.try_into().unwrap();
        copy[0] &= 0xf8;
        copy[31] |= 0x40;
        // Else the search for the first piece finds the scalar itself
        assert!(copy[..8] != scalar[..8]);
        Self(copy)
    }

    /// The copy in 8-byte pieces, since code after the assembly overwrites parts of its stack.
    /// The middle pieces equal the scalar's, and the first one differs from it.
    pub fn pieces(&self, name: &'static str) -> [(&'static str, &[u8]); 4] {
        [0, 8, 16, 24].map(|at| (name, &self.0[at..at + 8]))
    }
}

/// `X25519(scalar, point)` with `x`.
fn x25519(x: &mut impl X25519, scalar: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    *x.shared_secret(&X25519SecretKey::new(scalar), &point.into())
        .expose_secret()
}

/// Prints the rows and runs the tests.
pub fn rows() {
    println!();
    println!("  X25519 alone, RFC 7748 section 6.1:");
    x25519_rows();
    rfc_7748();
    wycheproof();
    differential();
    draft_vectors::<OtfMlKem768>("mlkem-otf");
    draft_vectors::<RustCryptoMlKem768>("ml-kem");
    residue();
    constant_time("cortex-m", &mut CortexMX25519);
    constant_time("dalek", &mut DalekX25519);
}

/// One X25519 with each backend, and the assembly without the wipe.
fn x25519_rows() {
    let alice = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let clamped_alice = Clamped::new(&alice);
    let bob = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let secret = X25519SecretKey::new(alice);
    let peer = X25519PublicKey::from(bob);
    let c = clamped_alice.pieces("its clamped copy");
    let clamped = clamp(&alice);
    let copies = [
        ("the scalar", &alice[..]),
        ("the clamped scalar", &clamped),
        ("the shared secret", &shared),
        c[0],
        c[1],
        c[2],
        c[3],
    ];
    let point = second_point(&alice, &bob, &shared);
    let leaks = Leaks {
        copies: &[&copies],
        ratios: &[
            ("the shared secret", &shared),
            ("the second ladder point", &point),
        ],
    };
    let out = measure("dalek", "X25519", &leaks, || {
        DalekX25519.shared_secret(black_box(&secret), black_box(&peer))
    });
    assert!(out.expose_secret() == &shared);
    let out = measure("cortex-m", "X25519", &leaks, || {
        CortexMX25519.shared_secret(black_box(&secret), black_box(&peer))
    });
    assert!(out.expose_secret() == &shared);

    // Positive control: without the wipe, the clamped scalar and the projective result stay on
    // the stack
    let (out, _, left) = run(&Leaks::copies(&[&c]), || {
        Unwiped.shared_secret(black_box(&secret), black_box(&peer))
    });
    assert!(left.is_some(), "no residue without the wipe");
    assert!(out.expose_secret() == &shared);
    let ratio = Leaks {
        copies: &[],
        ratios: &[("the shared secret", &shared)],
    };
    let (_, _, left) = run(&ratio, || {
        Unwiped.shared_secret(black_box(&secret), black_box(&peer))
    });
    assert!(left.is_some(), "no projective result without the wipe");

    let (stack, instructions) = assembly(&alice, &bob);
    println!(
        "  {:<44} {stack:>7} {instructions:>11}",
        "cortex-m assembly alone"
    );
    // The wrapper wipes 640 bytes, for the assembly and an exception frame of up to 212 bytes
    assert!(stack + 212 <= 640);
}

/// Peak stack and instructions of the assembly alone, from the stack pointer at its call.
#[inline(never)]
fn assembly(scalar: &[u8; 32], point: &[u8; 32]) -> (usize, u32) {
    let bottom = (&raw const crate::_stack_end).cast_mut();
    let sp = cortex_m::register::msp::read() as *mut u32;
    // SAFETY: Everything from the end of the stack up to the stack pointer is unused.
    let free = unsafe { sp.offset_from(bottom) } as usize;
    for i in 0..free {
        // SAFETY: In bounds of the unused stack, see above.
        unsafe { bottom.add(i).write_volatile(crate::PAINT) };
    }
    let mut result = [0; 32];
    let start = instructions();
    // SAFETY: Reads 32 bytes from `scalar` and `point` and writes 32 bytes to `result`. The
    // assembly saves r4-r11, uses no FPU register and may use the stack below `sp`.
    unsafe {
        core::arch::asm!(
            "bl {scalarmult}",
            scalarmult = sym xwing_embedded_0_1_curve25519_scalarmult,
            inout("r0") result.as_mut_ptr() => _,
            inout("r1") scalar.as_ptr() => _,
            inout("r2") point.as_ptr() => _,
            out("r3") _,
            out("r12") _,
            out("lr") _,
        )
    };
    let instructions = instructions().wrapping_sub(start);
    black_box(result);
    let mut untouched = 0;
    // SAFETY: In bounds of the unused stack, see above.
    while untouched < free && unsafe { bottom.add(untouched).read_volatile() } == crate::PAINT {
        untouched += 1;
    }
    ((free - untouched) * 4, instructions)
}

/// RFC 7748 sections 5.2 and 6.1.
fn rfc_7748() {
    let x = &mut CortexMX25519;
    for (scalar, u, out) in [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ] {
        assert!(x25519(x, h(scalar), h(u)) == h(out));
    }

    // Section 5.2, `k, u = X25519(k, u), k` from `k = u = 9`
    let mut k = X25519PublicKey::BASE_POINT.into();
    let mut u = k;
    for i in 1..=1000 {
        (k, u) = (x25519(x, k, u), k);
        if i == 1 {
            assert!(k == h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
        }
    }
    assert!(k == h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));

    // Section 6.1
    let a = X25519SecretKey::new(h(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b = X25519SecretKey::new(h(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let public_a = x.public_key(&a);
    let public_b = x.public_key(&b);
    assert!(
        public_a.as_ref() == &h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert!(
        public_b.as_ref() == &h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let k = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert!(x.shared_secret(&a, &public_b).expose_secret() == &k);
    assert!(x.shared_secret(&b, &public_a).expose_secret() == &k);
    println!("  RFC 7748 sections 5.2 and 6.1, 1000 iterations: ok");
}

/// Every Wycheproof X25519 vector, including twist points, low-order points, non-canonical
/// u-coordinates and all-zero results.
fn wycheproof() {
    let x = &mut CortexMX25519;
    for (i, v) in WYCHEPROOF.as_chunks::<96>().0.iter().enumerate() {
        let (&[private, public, shared], []) = v.as_chunks::<32>() else {
            unreachable!("96 bytes are three 32-byte values")
        };
        assert!(
            x25519(x, private, public) == shared,
            "Wycheproof vector {i}"
        );
    }
    println!(
        "  Wycheproof x25519_test.json, {} vectors: ok",
        WYCHEPROOF.len() / 96
    );
}

/// Random scalars and u-coordinates, all 256 bits random, against `x25519-dalek`.
fn differential() {
    let rng = &mut ChaCha20Rng::from_seed([7; 32]);
    for _ in 0..DIFFERENTIAL {
        let (mut scalar, mut point) = ([0; 32], [0; 32]);
        rng.fill_bytes(&mut scalar);
        rng.fill_bytes(&mut point);
        assert!(
            x25519(&mut CortexMX25519, scalar, point) == x25519(&mut DalekX25519, scalar, point)
        );
        let secret = X25519SecretKey::new(scalar);
        assert!(CortexMX25519.public_key(&secret) == DalekX25519.public_key(&secret));
    }
    println!("  Against x25519-dalek, {DIFFERENTIAL} random inputs: ok");
}

/// The three draft-11 vectors with the ML-KEM-768 `M` and this X25519.
fn draft_vectors<M: MlKem768 + Default>(name: &str) {
    let kem = &mut XWing {
        ml_kem: M::default(),
        x25519: CortexMX25519,
    };
    for v in vectors() {
        let mut slot = DecapsulationKeySlot::new();
        let secret_key = DecapsulationKey::from_seed(&mut slot, &mut v.sk.clone());
        let mut public = EncapsulationKey::from([0xff; 1216]);
        kem.encapsulation_key(secret_key, &mut public);
        assert!(public.as_ref() == v.pk);
        let mut key_slot = ExpandedKeySlot::new();
        // The encapsulation key is the one of the decapsulation key
        let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
        // The encapsulation key is valid
        let peer = kem.check(&public).unwrap();
        let mut ciphertext = Ciphertext::from([0xff; 1120]);
        let secret = kem.encapsulate(&mut FixedRng(v.eseed), &peer, &mut ciphertext);
        assert!(ciphertext.as_ref() == v.ct && secret.expose_secret() == v.ss);
        assert!(kem.decapsulate(&key, &ciphertext).expose_secret() == v.ss);
    }
    println!("  Draft-11 vectors with {name}: ok");
}

/// Checks that X-Wing with this X25519 leaves none of its secrets on the stack, for each
/// draft-11 vector. [`Stub`] stands in for ML-KEM-768, which would overwrite most of the stack.
/// The positive control runs the same with the unwiped assembly.
fn residue() {
    for v in vectors() {
        residue_of(&v);
    }
    println!("  No secret on the stack after each X-Wing operation: ok");
}

fn residue_of(v: &Vector) {
    let kem = &mut XWing {
        ml_kem: Stub,
        x25519: CortexMX25519,
    };
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = DecapsulationKey::from_seed(&mut slot, &mut black_box(v.sk).clone());
    let sk_x = &v.sk_x[..];
    let (m, ek_x) = v.eseed.split_at(32);
    let (clamped_sk_x, clamped_ek_x) = (Clamped::new(sk_x), Clamped::new(ek_x));
    let (c, e) = (
        clamped_sk_x.pieces("clamped sk_X"),
        clamped_ek_x.pieces("clamped ek_X"),
    );
    let mut public = EncapsulationKey::from([0; 1216]);
    // The stub's encapsulation key has the real X25519 part
    let pk_x = DalekX25519.public_key(&X25519SecretKey::new(*v.sk_x));
    let ss_x = x25519(
        &mut DalekX25519,
        ek_x.try_into().unwrap_or_else(|_| unreachable!()),
        pk_x.into(),
    );

    let seed = [
        ("sk_X", sk_x),
        ("clamped sk_X", &clamped_sk_x.0[..]),
        c[0],
        c[1],
        c[2],
        c[3],
    ];
    let long_term = [&seed[..]];
    let long_term = Leaks::copies(&long_term);
    checked("stub/cortex-m", "encapsulation_key", &long_term, || {
        kem.encapsulation_key(black_box(secret_key), &mut public)
    });
    let mut key_slot = ExpandedKeySlot::new();
    let (k, slot, own) = (&mut *kem, &mut key_slot, &public);
    let key = checked("stub/cortex-m", "expand", &long_term, move || {
        // The stub accepts every key
        k.expand(slot, black_box(secret_key), black_box(own))
            .unwrap()
    })
    .0;
    checked(
        "stub/cortex-m",
        "expand into a dropped slot",
        &long_term,
        || {
            let mut slot = ExpandedKeySlot::new();
            // The stub accepts every key
            black_box(
                kem.expand(&mut slot, black_box(secret_key), black_box(&public))
                    .unwrap(),
            );
        },
    );
    // The stub accepts every key
    let peer = kem.check(&public).unwrap();
    let mut ciphertext = Ciphertext::from([0; 1120]);
    // The shared secret with the stub, to search for it
    let shared = *kem
        .encapsulate(&mut FixedRng(v.eseed), &peer, &mut ciphertext)
        .expose_secret();
    let encapsulate_point = second_point(ek_x, pk_x.as_ref(), &ss_x);
    let decapsulate_point = second_point(sk_x, &ciphertext.as_ref()[1088..], &ss_x);
    let encapsulate = [
        ("m", m),
        ("ek_X", ek_x),
        ("ss_X", &ss_x[..]),
        ("the shared secret", &shared[..]),
        e[0],
        e[1],
        e[2],
        e[3],
    ];
    checked(
        "stub/cortex-m",
        "encapsulate",
        &Leaks {
            copies: &[&encapsulate, &seed],
            ratios: &[("ss_X", &ss_x), ("u([k + 1] pk_X)", &encapsulate_point)],
        },
        || kem.encapsulate(&mut FixedRng(v.eseed), black_box(&peer), &mut ciphertext),
    );
    let decapsulate = [("ss_X", &ss_x[..]), ("the shared secret", &shared[..])];
    let secret = checked(
        "stub/cortex-m",
        "decapsulate",
        &Leaks {
            copies: &[&decapsulate, &seed],
            ratios: &[("ss_X", &ss_x), ("u([k + 1] ct_X)", &decapsulate_point)],
        },
        || kem.decapsulate(black_box(&key), black_box(&ciphertext)),
    )
    .0;
    assert!(secret.expose_secret() == &shared);

    // Positive control, without the wipe. In `encapsulation_key` X25519 runs last, while in
    // `encapsulate` and `decapsulate` the combiner overwrites most of its stack.
    let unwiped = &mut XWing {
        ml_kem: Stub,
        x25519: Unwiped,
    };
    let mut public = EncapsulationKey::from([0; 1216]);
    let (_, _, left) = run(&Leaks::copies(&[&c]), || {
        unwiped.encapsulation_key(black_box(secret_key), &mut public)
    });
    assert!(left.is_some(), "no residue without the wipe");
}

/// The same instruction count of the X25519 `x` for scalars and u-coordinates of different values
/// and weights.
fn constant_time(name: &str, x: &mut impl X25519) {
    let rng = &mut ChaCha20Rng::from_seed([8; 32]);
    let mut inputs = [[0; 32]; 8];
    for input in &mut inputs[4..] {
        rng.fill_bytes(input);
    }
    inputs[1] = [0xff; 32];
    inputs[2] = X25519PublicKey::BASE_POINT.into();
    inputs[3][31] = 0x80;
    let mut count = None;
    for scalar in inputs {
        for point in inputs {
            let secret = X25519SecretKey::new(scalar);
            let peer = X25519PublicKey::from(point);
            let start = instructions();
            black_box(x.shared_secret(black_box(&secret), black_box(&peer)));
            let n = instructions().wrapping_sub(start);
            assert!(
                *count.get_or_insert(n) == n,
                "{name}: {n} instructions, not {count:?}"
            );
        }
    }
    println!(
        "  Constant time {name}, {} inputs: {} instructions each",
        inputs.len() * inputs.len(),
        count.unwrap_or(0)
    );
}
