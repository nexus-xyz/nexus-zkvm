#![allow(dead_code)]
#![allow(non_snake_case)]

pub mod error;
pub mod instructions;
mod memory;
pub mod eval;
pub mod trace;

mod ark_serde;
pub mod riscv;
