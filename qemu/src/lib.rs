//! Peak stack, instruction count and stack residue of X-Wing operations on a Cortex-M in QEMU.
//!
//! Each measurement fills the free stack with a pattern, runs the operation and finds the lowest
//! word that changed. The instruction count comes from the `icount.c` QEMU plugin and is exact.
//!
//! After an operation it copies the stack that the operation used and fails if the copy holds a
//! secret. It searches for byte copies at any address, for 32-byte secrets also as field
//! elements modulo 2^255 - 19 in the forms that the X25519 implementations keep, and for X25519
//! results and second ladder points also as projective pairs `(U, W)` with `U = secret * W`, see
//! [`Leaks`].
#![no_std]

use core::{
    convert::Infallible,
    hint::black_box,
    sync::atomic::{AtomicU32, Ordering},
};

use rand_core::{TryCryptoRng, TryRng, utils};
use semihosting::println;
use xwing_embedded::{
    InvalidEncapsulationKey, KeyMismatch, MlKem768, MlKemSharedSecret, X25519, X25519PublicKey,
    X25519SecretKey, X25519SharedSecret,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod field;
pub mod x25519_cortex_m;

use field::Fe;

pub static SK: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/sk.bin"));
pub static ESEED: [u8; 64] = *include_bytes!(concat!(env!("OUT_DIR"), "/eseed.bin"));
pub static CT: [u8; 1120] = *include_bytes!(concat!(env!("OUT_DIR"), "/ct.bin"));
pub static SS: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/ss.bin"));
/// `SHAKE256(sk, 96 * 8)`, the expanded seed `d || z || sk_X`.
pub static EXPANDED: [u8; 96] = *include_bytes!(concat!(env!("OUT_DIR"), "/expanded.bin"));
/// The ML-KEM-768 seed of the secret vector.
pub static SIGMA: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/sigma.bin"));
/// The ML-KEM-768 encryption randomness `r` of the vector.
pub static R: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/r.bin"));
/// The ML-KEM-768 implicit rejection key of the vector's ciphertext.
pub static K_BAR: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/k_bar.bin"));

const PAINT: u32 = 0xa5a5_a5a5;

/// Words of stack that the residue search copies, more than the largest operation it checks.
const SNAPSHOT: usize = 12 * 1024;

/// The stack an operation used, copied before the search overwrites it.
static mut USED: [u32; SNAPSHOT] = [0; SNAPSHOT];

/// Every field element the copied stack can hold, sorted.
static mut CANDIDATES: [Fe; 2 * SNAPSHOT] = [[0; 8]; 2 * SNAPSHOT];

/// Instructions of [`call`] with an empty closure, which [`run`] subtracts.
static OVERHEAD: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    /// Lowest address of the stack, from the `cortex-m-rt` linker script.
    static _stack_end: u32;
    static __stext: u32;
    static __etext: u32;
    static __srodata: u32;
    static __erodata: u32;
}

/// Measures the overhead of the instruction count.
pub fn init() {
    let ((), overhead) = call(|| ());
    OVERHEAD.store(overhead, Ordering::Relaxed);
}

/// Instructions executed so far, truncated to 32 bits.
#[inline(always)]
pub fn instructions() -> u32 {
    let n;
    // SAFETY: Moves r12 to itself. The plugin writes the instruction count into r12 first.
    unsafe { core::arch::asm!("mov r12, r12", out("r12") n, options(nostack, preserves_flags)) };
    n
}

/// Prints the size of `.text` and `.rodata` of this binary.
pub fn print_sizes() {
    let text = (&raw const __etext).addr() - (&raw const __stext).addr();
    let rodata = (&raw const __erodata).addr() - (&raw const __srodata).addr();
    println!("  {:<44} {text:>7}", ".text of this binary");
    println!("  {:<44} {rodata:>7}", ".rodata of this binary");
}

/// Returns the given bytes in order, to replay `eseed`.
pub struct FixedRng(pub &'static [u8]);

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let (head, tail) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = tail;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// Secrets by name, which an operation must not leave on the stack.
pub type Secrets<'a> = [(&'static str, &'a [u8])];

/// What an operation must not leave on the stack.
#[derive(Clone, Copy, Default)]
pub struct Leaks<'a> {
    /// Found as bytes at any address, and those of 32 bytes also as a field element in 8 words
    /// (the `x25519-cortex-m` form, possibly `value + p`) or in 10 limbs of radix 2^25.5 (the
    /// `FieldElement2625` of `curve25519-dalek`, possibly not fully reduced).
    pub copies: &'a [&'a Secrets<'a>],
    /// X25519 results and second ladder points, see [`second_point`], also found as a projective
    /// pair `(U, W)` of field elements in either form, anywhere on the stack, with
    /// `U = secret * W mod p` and `W != 0`.
    pub ratios: &'a [(&'static str, &'a [u8; 32])],
}

impl<'a> Leaks<'a> {
    /// Byte and field element copies of `copies`.
    pub const fn copies(copies: &'a [&'a Secrets<'a>]) -> Self {
        Self {
            copies,
            ratios: &[],
        }
    }
}

/// How a secret was found on the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    Bytes,
    FieldElement,
    ProjectivePair,
}

/// Peak stack in bytes and executed instructions of one call.
pub struct Usage {
    pub stack: usize,
    pub instructions: u32,
}

/// Prints a row of the table.
pub fn row(backend: &str, operation: &str, usage: &Usage) {
    println!(
        "  {backend:<18} {operation:<25} {:>7} {:>11}",
        usage.stack, usage.instructions
    );
}

/// Runs `f`, prints its usage and fails if it left one of `leaks` on the stack, see [`run`].
pub fn measure<R>(backend: &str, operation: &str, leaks: &Leaks, f: impl FnOnce() -> R) -> R {
    let (result, usage) = checked(backend, operation, leaks, f);
    row(backend, operation, &usage);
    result
}

/// Runs `f` and fails if it left one of `leaks` on the stack, see [`run`].
pub fn checked<R>(
    backend: &str,
    operation: &str,
    leaks: &Leaks,
    f: impl FnOnce() -> R,
) -> (R, Usage) {
    let (result, usage, left) = run(leaks, f);
    if let Some((secret, found)) = left {
        panic!("{backend} {operation} left {secret} on the stack, found as {found:?}");
    }
    (result, usage)
}

/// Runs `f` on a painted stack and returns its result, its usage and the first of `leaks` that
/// it left on the stack. Captures and the return value live in the caller's frame and are not
/// counted, and neither is the call itself.
#[inline(never)]
pub fn run<R>(leaks: &Leaks, f: impl FnOnce() -> R) -> (R, Usage, Option<(&'static str, Found)>) {
    let bottom = (&raw const _stack_end).cast_mut();
    let sp = cortex_m::register::msp::read() as *mut u32;
    // SAFETY: Everything from the end of the stack up to the stack pointer is unused.
    let free = unsafe { sp.offset_from(bottom) } as usize;
    for i in 0..free {
        // SAFETY: In bounds of the unused stack, see above.
        unsafe { bottom.add(i).write_volatile(PAINT) };
    }
    let (result, instructions) = call(f);
    // The scan and the copy read the stack that `f` used, so they make no calls
    let mut untouched = 0;
    // SAFETY: In bounds of the unused stack, see above.
    while untouched < free && unsafe { bottom.add(untouched).read_volatile() } == PAINT {
        untouched += 1;
    }
    assert!(untouched > 0, "stack overflow");
    let used = free - untouched;
    let searched = !leaks.copies.is_empty() || !leaks.ratios.is_empty();
    let copied = if searched { used } else { 0 };
    assert!(copied <= SNAPSHOT, "the snapshot is too small");
    let snapshot = (&raw mut USED).cast::<u32>();
    let mut i = 0;
    while i < copied {
        // SAFETY: In bounds of the unused stack and of `USED`, see above. Only this function
        // accesses `USED`, and there is one thread.
        unsafe {
            snapshot
                .add(i)
                .write(bottom.add(untouched + i).read_volatile())
        };
        i += 1;
    }
    let usage = Usage {
        stack: used * 4,
        instructions: instructions - OVERHEAD.load(Ordering::Relaxed),
    };
    // SAFETY: See above, and the copy is done.
    let snapshot = unsafe { core::slice::from_raw_parts((&raw const USED).cast::<u32>(), copied) };
    (result, usage, search(snapshot, leaks))
}

/// The first of `leaks` in `stack`.
fn search(stack: &[u32], leaks: &Leaks) -> Option<(&'static str, Found)> {
    // SAFETY: A `u32` slice is a valid `u8` slice of four times the length.
    let bytes =
        unsafe { core::slice::from_raw_parts(stack.as_ptr().cast::<u8>(), stack.len() * 4) };
    for &(name, secret) in leaks.copies.iter().copied().flatten() {
        if bytes.windows(secret.len()).any(|w| w == secret) {
            return Some((name, Found::Bytes));
        }
    }
    let candidates = candidates(stack);
    for &(name, secret) in leaks.copies.iter().copied().flatten() {
        if let Ok(secret) = <&[u8; 32]>::try_from(secret)
            && candidates.binary_search(&field::from_bytes(secret)).is_ok()
        {
            return Some((name, Found::FieldElement));
        }
    }
    for &(name, secret) in leaks.ratios {
        if candidates.binary_search(&field::from_bytes(secret)).is_ok() {
            return Some((name, Found::FieldElement));
        }
        let secret = field::from_bytes(secret);
        let mut previous = None;
        for w in candidates.iter() {
            if previous != Some(w) {
                previous = Some(w);
                if candidates.binary_search(&field::mul(&secret, w)).is_ok() {
                    return Some((name, Found::ProjectivePair));
                }
            }
        }
    }
    None
}

/// The nonzero values of every 8-word and every 10-limb window of `stack`, sorted.
fn candidates(stack: &[u32]) -> &'static [Fe] {
    // SAFETY: Only this function accesses `CANDIDATES`, there is one thread, and the slice it
    // returned before is no longer used.
    let all = unsafe {
        core::slice::from_raw_parts_mut((&raw mut CANDIDATES).cast::<Fe>(), 2 * SNAPSHOT)
    };
    let mut n = 0;
    let windows = stack.windows(8).map(|w| field::words(w.iter().copied()));
    let limbs = stack.windows(10).map(|w| field::limbs(w.iter().copied()));
    for value in windows.chain(limbs) {
        if value != [0; 8] {
            all[n] = value;
            n += 1;
        }
    }
    let all = &mut all[..n];
    all.sort_unstable();
    all
}

/// Checks that the search finds field element and projective pair copies of the X25519 result
/// `secret`, in both forms.
pub fn search_controls(secret: &[u8; 32]) {
    let s = field::from_bytes(secret);
    let w = field::from_bytes(&[0x5c; 32]);
    let u = field::mul(&s, &w);
    // Limbs that are not carried, so not the canonical ones
    let mut limbs = field::to_limbs(&s);
    limbs[0] += 1 << 26;
    limbs[1] -= 1;
    assert!(field::limbs(limbs) == s && limbs[1] < 1 << 25);
    let planted: [(&[u32], Found); 4] = [
        (&limbs, Found::FieldElement),
        (&field::plus_p(&s), Found::FieldElement),
        (
            &pair(&field::to_limbs(&u), &field::to_limbs(&w)),
            Found::ProjectivePair,
        ),
        (&pair(&field::plus_p(&u), &w), Found::ProjectivePair),
    ];
    for (words, form) in planted {
        let leaks = Leaks {
            copies: &[],
            ratios: &[("the planted copy", secret)],
        };
        let (_, _, left) = run(&leaks, || plant(words));
        assert!(
            left == Some(("the planted copy", form)),
            "the search missed {form:?}"
        );
    }
}

/// `u` and `w` apart in `words`, so the search does not depend on them being next to each other.
fn pair(u: &[u32], w: &[u32]) -> [u32; 40] {
    let mut words = [PAINT; 40];
    words[..u.len()].copy_from_slice(u);
    words[20..][..w.len()].copy_from_slice(w);
    words
}

/// Leaves `words` on the stack, 4 KiB deep.
#[inline(never)]
fn plant(words: &[u32]) {
    let mut copy = [0; 1024];
    copy[..words.len()].copy_from_slice(black_box(words));
    black_box(&mut copy);
}

/// Calls `f` in its own frame, so its locals are below the painted stack pointer, and counts
/// its instructions.
#[inline(never)]
fn call<R>(f: impl FnOnce() -> R) -> (R, u32) {
    let start = instructions();
    let result = f();
    let end = instructions();
    (result, end.wrapping_sub(start))
}

/// The scalar X25519 multiplies by (RFC 7748 section 5), which is as secret as the X25519 secret
/// key.
pub fn clamp(scalar: &[u8]) -> [u8; 32] {
    // Both X25519 secret keys of the vector have 32 bytes
    let mut clamped: [u8; 32] = scalar.try_into().unwrap();
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    clamped
}

/// `u([k + 1] P)` for the clamped `scalar` `k` and `u(P) = point`, the second point that the
/// Montgomery ladder of `X25519(scalar, point) = result` ends with. With the public `u(P)` it
/// gives the result up to two candidates, so it is as secret as the result. Computed here, so
/// that the measured binaries call `curve25519-dalek` only through `DalekX25519`.
pub fn second_point(scalar: &[u8], point: &[u8], result: &[u8; 32]) -> [u8; 32] {
    // Points have 32 bytes
    let mut u: [u8; 32] = point.try_into().unwrap();
    u[31] &= 127;
    let (x0, x1) = field::ladder(&clamp(scalar), &field::from_bytes(&u));
    assert!(
        x0 == field::from_bytes(result),
        "the ladder computes another result"
    );
    field::to_bytes(&x1)
}

/// ML-KEM-768 and X25519 that only read their secrets in place. The software implementations
/// overwrite most of what the X-Wing code left on the stack before them, so the residue checks
/// also run with these.
pub struct Stub;

/// The key slot of [`Stub`], which holds nothing.
pub struct StubSlot;

impl Zeroize for StubSlot {
    fn zeroize(&mut self) {}
}

impl ZeroizeOnDrop for StubSlot {}

impl MlKem768 for Stub {
    type KeySlot = StubSlot;
    type ExpandedKey<'a> = ();
    type CheckedKey<'k> = ();

    const EMPTY_SLOT: StubSlot = StubSlot;

    fn encapsulation_key(&mut self, seed: &mut [u8; 64], _: &mut [u8; 1184]) {
        black_box(seed);
    }

    fn expand(
        &mut self,
        _: &mut StubSlot,
        seed: &mut [u8; 64],
        _: &[u8; 1184],
    ) -> Result<(), KeyMismatch> {
        black_box(seed);
        Ok(())
    }

    fn check(&mut self, _: &[u8; 1184]) -> Result<(), InvalidEncapsulationKey> {
        Ok(())
    }

    fn encapsulate(&mut self, _: &(), m: &[u8; 32], _: &mut [u8; 1088]) -> MlKemSharedSecret {
        black_box(m);
        MlKemSharedSecret::new([0; 32])
    }

    fn decapsulate(&mut self, _: &(), _: &[u8; 1088]) -> MlKemSharedSecret {
        MlKemSharedSecret::new([0; 32])
    }
}

impl X25519 for Stub {
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        _: &X25519PublicKey,
    ) -> X25519SharedSecret {
        black_box(secret.expose_secret());
        X25519SharedSecret::new([0; 32])
    }
}
