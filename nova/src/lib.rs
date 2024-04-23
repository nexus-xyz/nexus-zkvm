#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::large_enum_variant)]

mod absorb;
mod provider;
mod sparse;
mod utils;

pub mod circuits;
mod folding;
mod gadgets;

#[cfg(test)]
mod test_utils;

pub mod ccs;
pub mod commitment;
pub mod r1cs;

pub use circuits::{
    hypernova::{self}, // uses same StepCircuit trait as Nova
    nova::{self, StepCircuit},
    supernova::{self, NonUniformCircuit},
};
pub use provider::{pedersen, zeromorph, poseidon::poseidon_config};

pub(crate) const LOG_TARGET: &str = "nexus-nova";
