#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]

mod absorb;
mod multifold;
mod provider;
mod utils;

mod circuits;
mod gadgets;

mod nifs;

pub mod commitment;
pub mod pedersen;
pub mod r1cs;

pub use circuits::{PublicParams, RecursiveSNARK, StepCircuit};
pub use multifold::Error;
pub use provider::poseidon::poseidon_config;
