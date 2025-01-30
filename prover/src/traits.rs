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

use crate::trace::{
    eval::TraceEval,
    preprocessed::PreprocessedTraces,
    program_trace::{ProgramTraces, ProgramTracesBuilder},
    sidenote::SideNote,
    FinalizedTraces, ProgramStep, TracesBuilder,
};

use super::components::MAX_LOOKUP_TUPLE_SIZE;

pub trait ExecuteChip {
    type ExecutionResult;
    /// Execute a chip and return the result of the execution in 8-bit limbs.
    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult;
}

pub trait MachineChip {
    /// Called on each row during main trace generation.
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>, // None for padding
        program_traces: &mut ProgramTracesBuilder,
        side_note: &mut SideNote,
    );

    /// Called on each row during constraint evaluation.
    ///
    /// This method **should not** read masks from `eval`.
    /// (except from interaction trace within LogupAtRow implementation in stwo).
    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    );

    /// Called just once for generating the interaction trace.
    ///
    /// The signature of this method is intentionally similar to `gen_interaction_trace()` in stwo examples.
    /// This method isn't called row-by-row because stwo logup library fills 16 rows of the interaction trace at a time.
    fn fill_interaction_trace(
        _original_traces: &FinalizedTraces,
        _preprocessed_trace: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        _lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        vec![]
    }
}

#[impl_for_tuples(1, 25)]
impl MachineChip for Tuple {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        program_traces: &mut ProgramTracesBuilder,
        side_note: &mut SideNote,
    ) {
        for_tuples!( #( Tuple::fill_main_trace(traces, row_idx, vm_step, program_traces, side_note); )* );
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        for_tuples!( #( Tuple::add_constraints(eval, trace_eval, lookup_elements); )* );
    }

    fn fill_interaction_trace(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        program_traces: &ProgramTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut cap = 0;
        for_tuples!( #( cap += 1; )* );
        let mut ret = Vec::with_capacity(cap);

        let ret_mut = ret.spare_capacity_mut();

        rayon::scope(|s| {
            for_tuples!( #(
                let (slice, ret_mut) = ret_mut.split_at_mut(1);
                s.spawn(move |_| {
                    let eval = Tuple::fill_interaction_trace(original_traces, preprocessed_traces, program_traces, lookup_element);

                    slice[0].write(eval);
                });
            )* );
        });

        // SAFETY:
        // all values were initialized within rayon scope.
        unsafe {
            ret.set_len(cap);
        }
        ret.into_iter().flatten().collect()
    }
}
