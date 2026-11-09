//! X25519 from Emil Lenngren's Cortex-M4 assembly, vendored in `vendor/x25519-cortex-m4`.

use core::arch::{asm, global_asm};

use zeroize::Zeroizing;

use crate::{X25519, X25519PublicKey, X25519SecretKey, X25519SharedSecret};

global_asm!(
    include_str!("../vendor/x25519-cortex-m4/x25519-cortex-m4-gcc.s"),
    options(raw)
);

unsafe extern "C" {
    /// `result = X25519(scalar, point)`, with the scalar clamped. All three may be unaligned.
    fn xwing_embedded_0_1_curve25519_scalarmult(
        result: *mut u8,
        scalar: *const u8,
        point: *const u8,
    );
}

/// Bytes below the stack pointer zeroed after each call. The assembly uses 416 bytes. An
/// exception taken during it stacks at most 212 more. That is on ARMv8-M from Secure to
/// Non-secure state, with the additional state context, the FPU state and `FPCCR.TS` set.
const WIPE: usize = 640;

/// X25519 in Cortex-M assembly, from [X25519-Cortex-M4] by Emil Lenngren. Constant time.
///
/// It runs on ARMv7E-M, and on ARMv8-M Mainline when the DSP extension is enabled, for example
/// with `-C target-cpu=cortex-m33`. The DSP extension is optional on ARMv8-M Mainline, also on
/// the Cortex-M33, so the part must have it too. A part without it faults on the first DSP
/// instruction. On ARMv8-M Mainline it needs rustc 1.99, or `codegen-units = 1` and no LTO, since
/// older rustc otherwise fails with "instruction requires: dsp".
///
/// After each call it zeroes the 640 bytes of stack below its frame, so its scalar, its
/// intermediates and the exception frame of an interrupt during the call do not stay on the
/// stack. With its frame it uses 704 bytes of stack on a Cortex-M33 at opt-level s. An interrupt
/// handler that runs during the call can push registers that hold secret intermediates below the
/// wiped region, where they stay, so mask interrupts around the call or run it at the lowest
/// priority if that matters.
///
/// The keys and the result can be at any address in Normal memory, since the assembly reads and
/// writes them only with single `ldr` and `str`, which ARMv7-M and ARMv8-M Mainline allow
/// unaligned unless `SCB.CCR.UNALIGN_TRP` is set (it is clear after reset).
///
/// It is under its own license, see `vendor/x25519-cortex-m4/LICENSE.txt`. A redistribution in
/// binary form must reproduce its copyright notice, conditions and disclaimer in the
/// documentation or other materials, except as embedded into a Nordic Semiconductor ASA or
/// Dialog Semiconductor PLC integrated circuit in a product or a software update for such
/// product.
///
/// [X25519-Cortex-M4]: https://github.com/Emill/X25519-Cortex-M4
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CortexMX25519;

/// Writes `X25519(secret, point)` to `result` and zeroes the stack the assembly used.
fn scalarmult(result: &mut [u8; 32], secret: &X25519SecretKey, point: &X25519PublicKey) {
    // SAFETY: The function reads 32 bytes from `secret` and `point` and writes 32 bytes to
    // `result`. It saves r4-r11, uses no FPU register and clobbers r0-r3, r12, lr and the
    // flags, which the operands list. Asm without `nostack` may use the stack below `sp`, which
    // the call and the wipe do, and `sp` is back at its start value at the end.
    unsafe {
        asm!(
            // On ARMv8-M this faults on the stack limit before the wipe can write past it
            "sub sp, sp, #{wipe}",
            "add sp, sp, #{wipe}",
            "bl {scalarmult}",
            // Zero the stack below `sp` and the scratch registers
            "mov r1, sp",
            "sub r2, sp, #{wipe}",
            "movs r0, #0",
            "movs r3, #0",
            "mov r12, r0",
            "2:",
            "str r0, [r2], #4",
            "cmp r2, r1",
            "bne 2b",
            wipe = const WIPE,
            scalarmult = sym xwing_embedded_0_1_curve25519_scalarmult,
            inout("r0") result.as_mut_ptr() => _,
            inout("r1") secret.expose_secret().as_ptr() => _,
            inout("r2") point.as_ref().as_ptr() => _,
            out("r3") _,
            out("r12") _,
            out("lr") _,
        );
    }
}

impl X25519 for CortexMX25519 {
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        peer: &X25519PublicKey,
    ) -> X25519SharedSecret {
        // Wiped on drop, since the move into the result can leave a copy
        let mut shared = Zeroizing::new([0; 32]);
        scalarmult(&mut shared, secret, peer);
        X25519SharedSecret::new(*shared)
    }

    fn public_key(&mut self, secret: &X25519SecretKey) -> X25519PublicKey {
        let mut public = [0; 32];
        scalarmult(&mut public, secret, &X25519PublicKey::BASE_POINT);
        public.into()
    }
}
