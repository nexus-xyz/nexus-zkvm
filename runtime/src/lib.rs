#![cfg_attr(target_arch = "riscv32", no_std)]
#![doc = include_str!("../README.md")]

#[cfg(target_arch = "riscv32")]
mod runtime;
#[cfg(target_arch = "riscv32")]
pub use runtime::*;

pub use nexus_rt_macros::main;

mod ecalls;
pub use ecalls::*;
