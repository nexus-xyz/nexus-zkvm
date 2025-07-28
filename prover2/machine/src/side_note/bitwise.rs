use crate::components::BitwiseMultiplicities;

/// Lookup counters used by the prover to compute final multiplicities for bitwise instructions.
#[derive(Debug, Default)]
pub struct BitwiseAccumulators {
    pub(crate) bitwise_mults_and: BitwiseMultiplicities,
    pub(crate) bitwise_mults_or: BitwiseMultiplicities,
    pub(crate) bitwise_mults_xor: BitwiseMultiplicities,
}
