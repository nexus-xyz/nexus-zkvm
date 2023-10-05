#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

mod absorb;
mod multifold;
mod provider;
mod utils;

mod circuits;
mod gadgets;

mod nifs;

pub mod commitment;
pub mod r1cs;

pub use circuits::{PublicParams, RecursiveSNARK, StepCircuit};
pub use multifold::Error;
pub use provider::{pedersen, poseidon::poseidon_config};
