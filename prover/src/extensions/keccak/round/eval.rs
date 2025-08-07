use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::{
    components::{
        lookups::{
            KeccakBitNotAndLookupElements, KeccakBitRotateLookupElements,
            KeccakStateLookupElements, KeccakXorLookupElements,
        },
        AllLookupElements,
    },
    extensions::FrameworkEvalExt,
};

pub struct KeccakRoundEval {
    pub(crate) index: usize,
    pub(crate) log_size: u32,
    pub(crate) state_lookup_elements: KeccakStateLookupElements,
    pub(crate) xor_lookup_elements: KeccakXorLookupElements,
    pub(crate) bit_not_and_lookup_elements: KeccakBitNotAndLookupElements,
    pub(crate) bit_rotate_lookup_elements: KeccakBitRotateLookupElements,
}

impl FrameworkEval for KeccakRoundEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        super::constraints::KeccakRoundEval {
            index: self.index,
            eval,
            state_lookup_elements: &self.state_lookup_elements,
            xor_lookup_elements: &self.xor_lookup_elements,
            bit_not_and_lookup_elements: &self.bit_not_and_lookup_elements,
            bit_rotate_lookup_elements: &self.bit_rotate_lookup_elements,
        }
        .eval()
    }
}

impl FrameworkEvalExt for KeccakRoundEval {
    fn new(_: u32, _: &AllLookupElements) -> Self {
        panic!("keccak round eval must be constructed from the extension")
    }

    fn dummy(log_size: u32) -> Self {
        Self {
            index: 0,
            log_size,
            state_lookup_elements: KeccakStateLookupElements::dummy(),
            xor_lookup_elements: KeccakXorLookupElements::dummy(),
            bit_not_and_lookup_elements: KeccakBitNotAndLookupElements::dummy(),
            bit_rotate_lookup_elements: KeccakBitRotateLookupElements::dummy(),
        }
    }
}
