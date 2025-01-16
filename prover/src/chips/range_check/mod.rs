//! Range-checking implementation. Constrains certain columns to only contain values from a specified range,
//! optionally depending on a flag.
//!
//! This is done with the use of [`stwo_prover::constraint_framework::logup::LookupElements`]
//! (excluding {0, 1} bool check).
//!
//! Currently a verifier is not protected against summing up multiplicity of the tuple to the modulus of M31.
//! This may allow the prover to lookup invalid values, but it also requires using the same constrained tuple
//! exactly `M31::P` times.
//!
//! The current guard is to limit the size of the trace such that `2.pow(trace_log_size) * NUM_CHECKED_COLS < M31::P`
//! for every chip.

mod range128;
mod range16;
mod range256;
mod range32;
mod range8;
mod range_bool;

pub use self::{
    range128::Range128Chip, range16::Range16Chip, range256::Range256Chip, range32::Range32Chip,
    range8::Range8Chip, range_bool::RangeBoolChip,
};
