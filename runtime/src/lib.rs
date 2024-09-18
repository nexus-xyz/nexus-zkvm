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
