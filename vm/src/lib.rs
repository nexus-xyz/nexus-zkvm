// this particular feature is now stabilized (https://blog.rust-lang.org/2024/03/21/Rust-1.77.0.html#stabilized-apis), but cargo complains (I think) since a dependent component has not itself stabilized yet
#![feature(slice_first_last_chunk)]

pub mod cpu;
pub mod elf;
pub mod emulator;
pub mod error;
pub mod memory;
pub mod riscv;
pub mod system;
pub mod trace;

pub use crate::elf::WORD_SIZE;
