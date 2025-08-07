use stwo::{
    core::{fields::m31::BaseField, poly::circle::CanonicCoset, ColumnVec},
    prover::{
        backend::simd::{column::BaseColumn, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

/// Intermediate representation of the component trace.
pub struct ComponentTrace {
    pub log_size: u32,
    pub preprocessed_trace: Vec<BaseColumn>,
    pub original_trace: Vec<BaseColumn>,
}

impl ComponentTrace {
    pub fn to_circle_evaluation(
        &self,
        trace_idx: usize,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        let trace = match trace_idx {
            PREPROCESSED_TRACE_IDX => &self.preprocessed_trace,
            ORIGINAL_TRACE_IDX => &self.original_trace,
            _ => panic!("invalid trace index"),
        };
        let preprocessed = trace
            .iter()
            .map(|col| CircleEvaluation::new(domain, col.clone()))
            .collect();

        preprocessed
    }
}
