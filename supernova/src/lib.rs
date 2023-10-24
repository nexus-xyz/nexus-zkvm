#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::wrong_self_convention)]

mod absorb;
mod multifold;
mod nifs;
mod provider;
mod utils;

mod circuits;
mod gadgets;

#[cfg(test)]
mod test_utils;

pub mod commitment;
pub mod r1cs;

pub use circuits::{nova, StepCircuit};
pub use provider::{pedersen, poseidon::poseidon_config};

pub(crate) const LOG_TARGET: &str = "supernova";
