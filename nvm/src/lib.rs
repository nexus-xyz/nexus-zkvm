#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::field_reassign_with_default)]

pub mod error;
pub mod instructions;
mod memory;
pub mod eval;
pub mod trace;

mod ark_serde;
pub mod riscv;

pub mod circuit;
