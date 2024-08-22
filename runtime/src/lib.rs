#![cfg_attr(target_arch = "riscv32", no_std)]
#![doc = include_str!("../README.md")]

#[cfg(target_arch = "riscv32")]
mod runtime;
#[cfg(target_arch = "riscv32")]
pub use runtime::*;

#[cfg(target_arch = "riscv32")]
mod alloc;

pub use nexus_rt_macros::{main, profile};

mod ecalls;
pub use ecalls::*;
pub use postcard;
