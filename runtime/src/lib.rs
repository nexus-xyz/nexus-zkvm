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
pub(crate) const SYS_LOG: u32 = 0x200;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_EXIT: u32 = 0x201;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_READ_PRIVATE_INPUT: u32 = 0x400;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_CYCLE_COUNT: u32 = 0x401;
#[cfg(target_arch = "riscv32")]
#[allow(dead_code)]
pub(crate) const SYS_OVERWRITE_SP: u32 = 0x402;
#[cfg(target_arch = "riscv32")]
pub(crate) const SYS_ALLOC_ALIGNED: u32 = 0x403;
// Error codes.
#[cfg(target_arch = "riscv32")]
pub(crate) const EXIT_SUCCESS: u32 = 0;
#[cfg(target_arch = "riscv32")]
pub(crate) const EXIT_PANIC: u32 = 1;
// Constants.
#[cfg(target_arch = "riscv32")]
pub(crate) const WORD_SIZE: usize = 4;

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

/// Reads word from specified byte address of the public input.
#[macro_export]
macro_rules! read_input {
    ($i:expr) => {{
        let mut out: u32;
        unsafe {
            core::arch::asm!(
                "lw {0}, 0x80(x0)", // 0x80 stores the public input start address
                "add {0}, {0}, {1}",
                ".insn i 0b0101011, 0b000, {2}, 0({0})",
                out(reg) _,
                in(reg) $i,
                out(reg) out,
            );
        }
        out
    }};
}

/// Writes word to the public output at specified byte address.
#[macro_export]
macro_rules! write_output {
    ($i:expr, $data:expr) => {
        unsafe {
            core::arch::asm!(
                "lw {0}, 0x84(x0)", // 0x84 stores the output start address
                "add {0}, {0}, {1}",
                ".insn s 0b1011011, 0b000, {2}, 0({0})",
                out(reg) _,
                in(reg) $i,
                in(reg) $data,
            )
        }
    };
}
