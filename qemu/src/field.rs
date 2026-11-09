//! Arithmetic modulo p = 2^255 - 19, and the two forms X25519 implementations keep field
//! elements in, for the search of transformed copies on the stack.

use core::cmp::Ordering;

/// A field element, fully reduced, as 8 little-endian 32-bit words.
pub type Fe = [u32; 8];

const P: Fe = [
    0xffff_ffed,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0x7fff_ffff,
];

/// Bit offsets of the ten limbs of radix 2^25.5, as in `FieldElement2625` of `curve25519-dalek`.
const OFFSETS: [u32; 10] = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230];

fn compare(a: &Fe, b: &Fe) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

/// `a` reduced from below 2^256 to below p.
fn canonical(mut a: Fe) -> Fe {
    while compare(&a, &P) != Ordering::Less {
        let mut borrow = 0;
        for (a, p) in a.iter_mut().zip(P) {
            let (d, b1) = a.overflowing_sub(p);
            let (d, b2) = d.overflowing_sub(borrow);
            *a = d;
            borrow = u32::from(b1 | b2);
        }
    }
    a
}

/// A 512-bit integer modulo p, with 2^256 = 38 mod p.
fn reduce(wide: &[u32; 16]) -> Fe {
    let mut r = [0; 8];
    let mut carry = 0;
    for i in 0..8 {
        let t = u64::from(wide[i]) + 38 * u64::from(wide[i + 8]) + carry;
        r[i] = t as u32;
        carry = t >> 32;
    }
    while carry != 0 {
        let mut c = 38 * carry;
        for limb in &mut r {
            let t = u64::from(*limb) + c;
            *limb = t as u32;
            c = t >> 32;
        }
        carry = c;
    }
    canonical(r)
}

/// `a * b mod p`.
pub fn mul(a: &Fe, b: &Fe) -> Fe {
    let mut wide = [0; 16];
    for i in 0..8 {
        let mut carry = 0;
        for j in 0..8 {
            let t = u64::from(a[i]) * u64::from(b[j]) + u64::from(wide[i + j]) + carry;
            wide[i + j] = t as u32;
            carry = t >> 32;
        }
        wide[i + 8] = carry as u32;
    }
    reduce(&wide)
}

/// `a + b mod p`.
pub fn add(a: &Fe, b: &Fe) -> Fe {
    let mut wide = [0; 16];
    let mut carry = 0;
    for i in 0..8 {
        let t = u64::from(a[i]) + u64::from(b[i]) + carry;
        wide[i] = t as u32;
        carry = t >> 32;
    }
    wide[8] = carry as u32;
    reduce(&wide)
}

/// The 256-bit little-endian integer of `bytes`, modulo p.
pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
    words(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_le_bytes(*w)),
    )
}

/// The 256-bit integer of 8 little-endian words, modulo p. This is the form of the
/// `x25519-cortex-m` assembly, which keeps values below 2^256, so possibly `value + p`.
pub fn words(words: impl IntoIterator<Item = u32>) -> Fe {
    let mut wide = [0; 16];
    for (w, word) in wide.iter_mut().zip(words) {
        *w = word;
    }
    reduce(&wide)
}

/// The value of ten limbs of radix 2^25.5, modulo p. Limbs may be above 2^26, as in a
/// `FieldElement2625` that is not fully reduced.
pub fn limbs(limbs: impl IntoIterator<Item = u32>) -> Fe {
    let mut wide = [0; 16];
    for (limb, offset) in limbs.into_iter().zip(OFFSETS) {
        let mut k = (offset / 32) as usize;
        let mut carry = u64::from(limb) << (offset % 32);
        while carry != 0 {
            let t = u64::from(wide[k]) + (carry & 0xffff_ffff);
            wide[k] = t as u32;
            carry = (carry >> 32) + (t >> 32);
            k += 1;
        }
    }
    reduce(&wide)
}

/// The fully carried ten limbs of `a`.
pub fn to_limbs(a: &Fe) -> [u32; 10] {
    core::array::from_fn(|i| {
        let (offset, width) = (OFFSETS[i], 26 - i as u32 % 2);
        let word = (offset / 32) as usize;
        let high = a.get(word + 1).copied().unwrap_or(0);
        let both = u64::from(a[word]) | u64::from(high) << 32;
        (both >> (offset % 32)) as u32 & ((1 << width) - 1)
    })
}

/// `a + p`, below 2^256 since `a` is below p.
pub fn plus_p(a: &Fe) -> Fe {
    let mut r = [0; 8];
    let mut carry = 0;
    for i in 0..8 {
        let t = u64::from(a[i]) + u64::from(P[i]) + carry;
        r[i] = t as u32;
        carry = t >> 32;
    }
    r
}

/// `a - b mod p`.
pub fn sub(a: &Fe, b: &Fe) -> Fe {
    let b = canonical(*b);
    let mut minus_b = [0; 8];
    let mut borrow = 0;
    for i in 0..8 {
        let (d, b1) = P[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        minus_b[i] = d;
        borrow = u32::from(b1 | b2);
    }
    add(a, &minus_b)
}

/// `a^(p - 2) mod p`, the inverse of `a`, or 0 for 0.
fn invert(a: &Fe) -> Fe {
    let mut e = P;
    e[0] -= 2;
    let mut r = [1, 0, 0, 0, 0, 0, 0, 0];
    for i in (0..255).rev() {
        r = mul(&r, &r);
        if (e[i / 32] >> (i % 32)) & 1 == 1 {
            r = mul(&r, a);
        }
    }
    r
}

/// The Montgomery ladder of RFC 7748 section 5 for the clamped scalar `k`, returning the affine
/// `u([k] P)` and `u([k + 1] P)` for `u(P) = u`. Not constant time.
pub fn ladder(k: &[u8; 32], u: &Fe) -> (Fe, Fe) {
    let one = [1, 0, 0, 0, 0, 0, 0, 0];
    let a24 = [121665, 0, 0, 0, 0, 0, 0, 0];
    let (mut x2, mut z2, mut x3, mut z3) = (one, [0; 8], *u, one);
    let mut swap = false;
    for t in (0..255).rev() {
        let bit = (k[t / 8] >> (t % 8)) & 1 == 1;
        if swap != bit {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;
        let a = add(&x2, &z2);
        let aa = mul(&a, &a);
        let b = sub(&x2, &z2);
        let bb = mul(&b, &b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        let sum = add(&da, &cb);
        let difference = sub(&da, &cb);
        x3 = mul(&sum, &sum);
        z3 = mul(u, &mul(&difference, &difference));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul(&a24, &e)));
    }
    if swap {
        core::mem::swap(&mut x2, &mut x3);
        core::mem::swap(&mut z2, &mut z3);
    }
    (mul(&x2, &invert(&z2)), mul(&x3, &invert(&z3)))
}

/// The 32 little-endian bytes of `a`.
pub fn to_bytes(a: &Fe) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(a) {
        *chunk = word.to_le_bytes();
    }
    bytes
}
