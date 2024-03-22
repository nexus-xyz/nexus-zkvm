#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::field_reassign_with_default)]

// We rely on this in cacheline.rs
#[cfg(not(target_endian = "little"))]
compile_error!("Host must be little-endian");

pub mod error;
pub mod eval;
pub mod instructions;
pub mod trace;

mod ark_serde;
pub mod memory;

pub mod circuit;
