#![cfg_attr(target_arch = "riscv32", no_std)]
#![doc = include_str!("../README.md")]

#[cfg(target_arch = "riscv32")]
mod runtime;

#[cfg(target_arch = "riscv32")]
pub use runtime::*;

#[cfg(target_arch = "riscv32")]
mod alloc;

pub use nexus_rt_macros::{
    custom_input, custom_output, main, private_input, profile, public_input, public_output,
};

mod io;
pub use io::*;
pub use postcard;

// Ecall codes. Allow dead code here because these are only used in the RISC-V runtime, not when
// compiling for the host.
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_LOG: u32 = 512;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_EXIT: u32 = 513;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_READ_PRIVATE_INPUT: u32 = 1024;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_CYCLE_COUNT: u32 = 1025;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_OVERWRITE_SP: u32 = 1026;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_ALLOC_ALIGNED: u32 = 1027;
// Error codes.
#[cfg(target_arch = "riscv32")]
pub(crate) const PANIC_ERROR_CODE: u32 = 1;

/// Macro for making an ecall with variable number of parameters:
/// - First parameter: syscall code (placed in a7)
/// - Last parameter: output (returned in a0)
/// - Intermediate parameters: inputs (if any, from a0 to a6)
#[macro_export]
macro_rules! ecall {
    ($code:expr, $input_0:expr, $(($reg:tt, $input:expr)),*) => {{
        let mut out: u32;
        unsafe {
            core::arch::asm!(
                "ecall",
                inout("a0") $input_0 => out,
                in("a7") $code,
                $(
                    in($reg) $input,
                )*
            )
        }
        out
    }};
    ($code:expr, $input_0:expr) => {{
        let mut out: u32;
        unsafe {
            core::arch::asm!(
                "ecall",
                inout("a0") $input_0 => out,
                in("a7") $code,
            )
        }
        out
    }};
    ($code:expr) => {{
        let mut out: u32;
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") $code,
                out("a0") out,
            )
        }
        out
    }};
}
