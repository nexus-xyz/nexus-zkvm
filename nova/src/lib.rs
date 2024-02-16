#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::large_enum_variant)]

mod absorb;
mod provider;
mod utils;

mod circuits;
mod folding;
mod gadgets;

#[cfg(test)]
mod test_utils;

pub mod commitment;
pub mod r1cs;

pub use circuits::{nova, StepCircuit};
pub use provider::{pedersen, poseidon::poseidon_config};

pub(crate) const LOG_TARGET: &str = "nexus-nova";
