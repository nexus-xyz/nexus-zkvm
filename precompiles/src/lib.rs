#![cfg_attr(target_arch = "riscv32", no_std)]

#[cfg(not(target_arch = "riscv32"))]
mod traits;
#[cfg(not(target_arch = "riscv32"))]
pub use traits::*;

pub use nexus_precompile_macros::use_precompiles;
