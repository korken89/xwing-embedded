# xwing-embedded

X-Wing, the hybrid KEM of ML-KEM-768 and X25519 ([draft-connolly-cfrg-xwing-kem-11]), for
microcontrollers.

- ML-KEM-768 and X25519 are traits, so a target can plug in its own implementations, for example
  X25519 in assembly. The X-Wing combiner and the key expansion stay in this crate.
- The default ML-KEM-768 is [`mlkem-otf`], which streams the matrix and the secret vector, so
  every operation fits in about 3 kB of stack.
- The optional `x25519-cortex-m` feature has an X25519 in Cortex-M assembly, which is about five
  times as fast as the software X25519 and uses about a quarter of its stack.
- The decapsulation key is expanded once and a peer's encapsulation key is checked once. Both
  borrow the encapsulation key where it is stored or received.
- Secret keys are filled in place into slots that the caller provides, for example in a `static`,
  and are never moved.
- Ciphertexts and encapsulation keys are written into the caller's buffer.
- `no_std`, no allocation, and secrets are wiped on drop. There is no `unsafe` outside the
  `x25519-cortex-m` backend.

[`mlkem-otf`]: https://github.com/korken89/mlkem-otf
[draft-connolly-cfrg-xwing-kem-11]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/11/

## Security warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

The default ML-KEM-768, `mlkem-otf`, is new and has never been independently audited either.

There is no protection against fault injection, such as voltage glitches.

`DecapsulationKey::from_seed` and `generate` fill the seed in place, in a `DecapsulationKeySlot`
that the caller provides, and `expand` fills the X25519 secret key and the ML-KEM-768 key in
place, in an `ExpandedKeySlot`. Both lend the key out by shared reference only, so it is never
moved. A slot can be a `static`, for example in a `ConstStaticCell`, or on the stack, and it is
wiped when it is dropped. A key that is already in the slot is wiped before the slot is filled
again. Moving a slot that holds a key copies the key, so keep the slot where it is.
`from_seed` wipes the caller's copy of the seed. The `ExpandedKey` that `expand` returns borrows
its slot and holds no secret of its own, so it can be moved freely. The RustCrypto `ml-kem` crate
returns its decoded decapsulation key by value, so with `RustCryptoMlKem768`, `expand` and
`encapsulation_key` leave copies of it, which hold `d` and `z`, on the stack.

Per-operation secrets are wiped. `make test-qemu` fails if loading the seed, `encapsulation_key`,
`expand`, `check`, `encapsulate` or `decapsulate` with `mlkem-otf` and either X25519 leaves a
secret of the operation or the decapsulation key on the stack below the caller, at opt-level s, 2,
3 and z. It searches for the seed, `d || z`, `d`, `z`, the ML-KEM-768 seed of the secret vector,
`sk_X` and the clamped `sk_X` after the key is loaded and expanded into a slot, also into a slot
on the stack of the operation that is then dropped, and after every operation. The checks search
for byte copies of each secret, for the X25519 secret keys also for clamped copies, and for
32-byte secrets also for the field elements that the X25519 implementations keep: 8 words,
possibly `value + p`, or 10 limbs of radix 2^25.5, possibly not fully reduced. They also search
for an X25519 result and for the second point of the ladder, `u([k + 1] P)`, as a projective pair
`(U, W)` with `U = value * W`. A part of a secret that the compiler spills to the stack, or another
transformed copy, is not found. The RustCrypto `ml-kem` crate leaves the ML-KEM-768 secrets of
decapsulation (`m`, `r` and the shared secret) on the stack, and at some opt-levels the seed of
the secret vector, which this crate cannot wipe.

`curve25519-dalek` leaves its ladder state on the stack, so `DalekX25519` runs the ladder in its
own frame and then zeroes 2,560 bytes of stack below its caller, or 4,096 bytes with debug
assertions. On ARMv7E-M and ARMv8-M the ladder uses up to 2,000 bytes from opt-level 1 up, and
3,600 bytes at opt-level 0. `make test-qemu` checks this on a Cortex-M33 and a Cortex-M4 at
opt-level s, 2, 3 and z with the pinned toolchain. Other targets, opt-levels and compilers can
use more stack, and then a part of the ladder state stays unwiped.

`CortexMX25519` (feature `x25519-cortex-m`) zeroes the 640 bytes of stack below its frame after
each call. This covers the 416 bytes the assembly uses and the largest exception frame, 212 bytes
on ARMv8-M from Secure to Non-secure state with the FPU state. With its frame it uses 704 bytes.

An interrupt taken during an operation pushes registers that can hold secret intermediates below
the wiped region, where they stay, so mask interrupts around the operation or run it at the
lowest priority if that matters.

`make test-qemu` also fails unless each X25519 takes the same number of instructions for 64
inputs, and decapsulation with `mlkem-otf` for the valid ciphertext and for ones with `ct_M` or
`ct_X` modified, at opt-level s, 2, 3 and z.

An all-zero X25519 output is accepted, as RFC 7748 section 6.1 allows. The draft does not say
what to do with it yet. This can change when the RFC is published.

## Usage

```rust
use static_cell::ConstStaticCell;
use xwing_embedded::{
    Ciphertext, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey, ExpandedKeySlot,
    OtfMlKem768, SoftwareXWing,
};

let kem = &mut SoftwareXWing::default();

// Provisioning: store the seed in secure storage and the encapsulation key where it can be read.
// The slot on the stack is wiped when it is dropped.
let mut seed = [0; 32];
rng.fill_bytes(&mut seed);
storage.write(&seed);
let mut slot = DecapsulationKeySlot::new();
let secret_key = DecapsulationKey::from_seed(&mut slot, &mut seed);
let mut public = EncapsulationKey::from([0; 1216]);
kem.encapsulation_key(secret_key, &mut public);
drop(slot);

// At start: load the seed, which wipes `seed`, expand it once into a static slot and check that
// `public` belongs to it
static KEY: ConstStaticCell<ExpandedKeySlot<OtfMlKem768>> =
    ConstStaticCell::new(ExpandedKeySlot::new());
storage.read(&mut seed);
let mut slot = DecapsulationKeySlot::new();
let secret_key = DecapsulationKey::from_seed(&mut slot, &mut seed);
let own = kem.expand(KEY.take(), secret_key, &public)?;
drop(slot);

// A peer checks the encapsulation key once and encapsulates to it
let peer = kem.check(&public)?;
let mut ciphertext = Ciphertext::from([0; 1120]);
let sent = kem.encapsulate(rng, &peer, &mut ciphertext);

let received = kem.decapsulate(&own, &ciphertext);
assert_eq!(sent.expose_secret(), received.expose_secret());
```

With an own X25519, for example one in assembly:

```rust
use xwing_embedded::{
    OtfMlKem768, X25519, X25519PublicKey, X25519SecretKey, X25519SharedSecret, XWing,
};
use zeroize::Zeroizing;

struct AsmX25519;

impl X25519 for AsmX25519 {
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        peer: &X25519PublicKey,
    ) -> X25519SharedSecret {
        // Wiped on drop, since the move into the result can leave a copy
        let mut out = Zeroizing::new([0; 32]);
        // Reads the secret in place and zeroes the stack it used
        asm::scalarmult(&mut out, secret.expose_secret(), peer.as_ref());
        X25519SharedSecret::new(*out)
    }
}

let kem = &mut XWing { ml_kem: OtfMlKem768, x25519: AsmX25519 };
```

`DecapsulationKey::generate` draws a seed that cannot be read back, so it is for keys that are not
stored. `DecapsulationKey::try_generate` and `XWing::try_encapsulate` take an RNG that can fail
(`TryCryptoRng`) and return its error.

An own X25519 must not leave a copy of the secret key on the stack, also not a clamped one, and
no intermediate value or copy of the result. So it reads the secret by reference, writes the
result into a buffer that is wiped on drop, and zeroes the stack it used, as `CortexMX25519` in
`src/cortex_m.rs` does.

## Features

| Feature           | Default | Adds                                                                   |
| ----------------- | ------- | ---------------------------------------------------------------------- |
| `mlkem-otf`       | yes     | `OtfMlKem768`, ML-KEM-768 with a small stack from `mlkem-otf`          |
| `x25519-dalek`    | yes     | `DalekX25519`, X25519 from `curve25519-dalek`                          |
| `ml-kem`          | no      | `RustCryptoMlKem768`, ML-KEM-768 from the RustCrypto `ml-kem` crate    |
| `x25519-cortex-m` | no      | `CortexMX25519`, X25519 in Cortex-M assembly by Emil Lenngren          |
| `defmt`           | no      | `defmt::Format` on the public value types and the errors               |
| `zerocopy`        | no      | zerocopy traits on `EncapsulationKey`, `Ciphertext`, `X25519PublicKey` |

`SoftwareXWing` needs both default features. With own components, set
`default-features = false`.

`x25519-cortex-m` builds for ARMv7E-M (`thumbv7em-*`), and for ARMv8-M Mainline
(`thumbv8m.main-*`) when the core has the DSP extension and the build says so, for example with
`-C target-cpu=cortex-m33`. The DSP extension is optional on ARMv8-M Mainline, also on the
Cortex-M33, so check that the part has it. A part without it faults on the first DSP instruction.
Other targets get a compile error, so `--all-features` builds only
for these targets. On ARMv8-M Mainline it needs rustc 1.99, or `codegen-units = 1` and no LTO,
since older rustc fails with "instruction requires: dsp". The keys and the result can be at any
address in Normal memory, since the assembly reads and writes them only with single `ldr` and
`str`, which ARMv7-M and ARMv8-M Mainline allow unaligned unless `SCB.CCR.UNALIGN_TRP` is set
(it is clear after reset). The assembly is under its own license, see [License](#license).

## Measurements

On a Cortex-M33 in QEMU (`mps2-an505`), draft-11 test vector 1, built with `opt-level = "s"`
and LTO, for `-C target-cpu=cortex-m33` since `x25519-cortex-m` needs the DSP extension. Stack
is the peak in bytes. Instructions are executed instructions, counted exactly by a QEMU plugin,
not cycles. The code size is what the operation adds to an empty binary, SHA-3 and X25519
included.

With `OtfMlKem768`, the configuration for a small stack, and each X25519:

| Operation           | `DalekX25519` stack | Instructions | .text (B) | `CortexMX25519` stack | Instructions | .text (B) |
| ------------------- | ------------------: | -----------: | --------: | --------------------: | -----------: | --------: |
| `encapsulation_key` |               2,856 |    4,165,461 |     8,676 |                 2,208 |    2,723,512 |     5,796 |
| `expand`            |               2,904 |    4,591,215 |     9,020 |                 2,208 |    3,149,266 |     6,176 |
| `check`             |                 552 |      430,470 |     1,176 |                   552 |      430,473 |     1,176 |
| `encapsulate`       |               2,760 |    6,321,732 |    10,276 |                 2,304 |    3,438,340 |     7,288 |
| `decapsulate`       |               2,776 |    5,321,291 |    12,052 |                 2,840 |    3,879,752 |     9,076 |
| All of the above    |                   - |            - |    13,956 |                     - |            - |    11,044 |

With `RustCryptoMlKem768` and each X25519:

| Operation           | `DalekX25519` stack | Instructions | .text (B) | `CortexMX25519` stack | Instructions | .text (B) |
| ------------------- | ------------------: | -----------: | --------: | --------------------: | -----------: | --------: |
| `encapsulation_key` |              36,536 |    4,632,344 |    11,792 |                36,536 |    3,190,395 |     8,924 |
| `expand`            |              36,496 |    4,638,892 |    12,044 |                36,504 |    3,196,946 |     9,196 |
| `check`             |              11,116 |      565,857 |     2,212 |                11,116 |      565,858 |     2,212 |
| `encapsulate`       |              28,536 |    6,200,085 |    15,608 |                28,624 |    3,316,655 |    12,620 |
| `decapsulate`       |              32,856 |    5,125,279 |    17,648 |                32,920 |    3,683,739 |    14,680 |
| All of the above    |                   - |            - |    18,952 |                     - |            - |    16,152 |

The code size of `encapsulate` includes `check`, and of `decapsulate` includes `expand`. The
expanded key slot takes 96 bytes with `mlkem-otf` and 3,234 bytes with `ml-kem`, the expanded key
that borrows it 48 and 12 bytes, and the checked key 40 and 1,604 bytes. The `ml-kem` `expand`
stack includes copies of the decoded key that the `ml-kem` crate returns by value.

One X25519 alone, on the Cortex-M33 and on a Cortex-M4 (`mps2-an386`, `thumbv7em-none-eabihf`):

| X25519             | Stack | M33 instructions | M4 instructions | .text (B) |
| ------------------ | ----: | ---------------: | --------------: | --------: |
| `DalekX25519`      | 2,664 |        1,809,247 |       1,680,348 |     5,244 |
| `CortexMX25519`    |   704 |          367,631 |         367,599 |     2,252 |
| the assembly alone |   416 |          366,944 |         366,944 |           |

The RustCrypto `x-wing` 0.1.1 crate, which expands the decapsulation key again in every
decapsulation, for comparison:

| Operation                   |  Stack | Instructions |
| --------------------------- | -----: | -----------: |
| `DecapsulationKey::from`    | 44,136 |    4,537,722 |
| `EncapsulationKey::new`     | 11,124 |      565,132 |
| `encapsulate_deterministic` | 29,640 |    6,124,899 |
| `decapsulate`               | 52,392 |    9,660,026 |

The exact stack and instruction counts are in [`qemu/measurements.txt`](qemu/measurements.txt)
and CI fails if they change. `make size` prints the code sizes.

## Testing

The flake has the toolchain and QEMU:

```console
$ nix develop
$ make test   # host tests, the QEMU measurements and the residue checks
$ make lint   # rustfmt, clippy and rustdoc
$ make size   # code size of each operation
$ make bless  # update qemu/measurements.txt after an intended change
```

The host tests run the draft-11 test vectors and the RFC 7748 X25519 vectors, and cross check
against the RustCrypto `x-wing` crate, including tampered ciphertexts, with each ML-KEM-768. They
also compare `mlkem-otf` with the RustCrypto `ml-kem` crate over 256 random keys, messages and
tampered ciphertexts, and `DalekX25519` with `x25519-dalek` over 256 random inputs. The
draft-11 vectors in `tests/data/draft-11.json` are from the
[`x-wing`](https://crates.io/crates/x-wing) crate by RustCrypto (MIT OR Apache-2.0).

On QEMU, on a Cortex-M33 and on a Cortex-M4, `CortexMX25519` runs the RFC 7748 vectors
including 1,000 iterations, the 518 [Wycheproof] vectors, 64 random inputs against
`x25519-dalek` and the draft-11 vectors with each ML-KEM-768. It also checks that it and
`DalekX25519` take the same number of instructions for 64 inputs, and that no scalar, clamped
scalar copy or X-Wing secret is left on the stack after each operation, for each draft-11 vector.
Positive controls show that the search finds the clamped scalar and the projective result of the
assembly without its stack wipe, the result of the `DalekX25519` ladder without its scrub, and
planted field element and projective pair copies in both forms. On the Cortex-M33, a negative
control shows that it finds nothing of an unrelated value. The Wycheproof vectors in
`tests/data/wycheproof-x25519.json` are `testvectors_v1/x25519_test.json` at commit
`d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (Apache-2.0).

[Wycheproof]: https://github.com/C2SP/wycheproof

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option,
except `vendor/x25519-cortex-m4`.

`vendor/x25519-cortex-m4` is [X25519-Cortex-M4] by Emil Lenngren, under its own license in
[`vendor/x25519-cortex-m4/LICENSE.txt`](vendor/x25519-cortex-m4/LICENSE.txt). It is not
plain BSD-2-Clause. Only the `x25519-cortex-m` feature builds it into a binary. Then clause 2
applies, so a redistribution in binary form must reproduce its copyright notice, conditions and
disclaimer in the documentation and/or other materials, except as embedded into a Nordic
Semiconductor ASA or Dialog Semiconductor PLC integrated circuit in a product or a software
update for such product. The license file has the full terms.

[X25519-Cortex-M4]: https://github.com/Emill/X25519-Cortex-M4
