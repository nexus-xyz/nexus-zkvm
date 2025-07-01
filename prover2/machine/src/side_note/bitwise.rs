use crate::components::BitwiseAccumulator;

/// Lookup counters used by the prover to compute final multiplicities for bitwise instructions.
#[derive(Debug, Default)]
pub struct BitwiseAccumulators {
    pub(crate) bitwise_accum_and: BitwiseAccumulator,
    pub(crate) bitwise_accum_or: BitwiseAccumulator,
    pub(crate) bitwise_accum_xor: BitwiseAccumulator,
}
