use impl_trait_for_tuples::impl_for_tuples;
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::{
        backend::simd::SimdBackend,
        fields::m31::BaseField,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use super::trace::{eval::TraceEval, ProgramStep, Traces};

/// The number of BaseField's in the biggest tuple we look up
pub const MAX_LOOKUP_TUPLE_SIZE: usize = 12;

pub trait MachineChip {
    /// Called on each row during main trace generation.
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep);

    /// Called on each row during constraint evaluation.
    ///
    /// This method **should not** read masks from `eval`.
    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>);

    /// Called just once for generating the interaction trace.
    ///
    /// The signature of this method is intentionally similar to `gen_interaction_trace()` in stwo examples.
    /// This method isn't called row-by-row because stwo logup library fills 16 rows of the interaction trace at a time.
    fn fill_interaction_trace(
        _original_traces: &Traces,
        _preprocessed_trace: &Traces,
        _lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        vec![]
    }
}

#[impl_for_tuples(1, 12)]
impl MachineChip for Tuple {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        for_tuples!( #( Tuple::fill_main_trace(traces, row_idx, vm_step); )* );
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        for_tuples!( #( Tuple::add_constraints(eval, trace_eval); )* );
    }

    fn fill_interaction_trace(
        original_traces: &Traces,
        preprocessed_traces: &Traces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut result = ColumnVec::new();
        for_tuples!( #( result.append(&mut Tuple::fill_interaction_trace(original_traces, preprocessed_traces, lookup_element)); )* );
        result
    }
}
