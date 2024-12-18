#![cfg_attr(target_arch = "riscv32", no_std)]

#[cfg(target_arch = "riscv32")]
pub mod guest;
#[cfg(target_arch = "riscv32")]
pub use guest::*;

#[cfg(not(target_arch = "riscv32"))]
pub mod host;
#[cfg(not(target_arch = "riscv32"))]
pub use host::*;
