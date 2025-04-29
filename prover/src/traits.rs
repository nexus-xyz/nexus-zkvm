use impl_trait_for_tuples::impl_for_tuples;

use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, EvalAtRow},
    core::{
        backend::simd::SimdBackend,
        channel::Channel,
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::TraceEval, preprocessed::PreprocessedTraces, program_trace::ProgramTraces,
        sidenote::SideNote, FinalizedTraces, ProgramStep, TracesBuilder,
    },
};

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
        side_note: &mut SideNote,
        config: &ExtensionsConfig,
    );

    /// Called on each row during constraint evaluation.
    ///
    /// This method **should not** read masks from `eval`.
    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
        config: &ExtensionsConfig,
    );

    /// Called just once for generating the interaction trace.
    ///
    /// The signature of this method is intentionally similar to `gen_interaction_trace()` in stwo examples.
    /// This method isn't called row-by-row because stwo logup library fills 16 rows of the interaction trace at a time.
    fn fill_interaction_trace(
        _logup_trace_gen: &mut LogupTraceGenerator,
        _original_traces: &FinalizedTraces,
        _preprocessed_trace: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        _lookup_elements: &AllLookupElements,
    ) {
    }

    /// Draw lookup elements required by the component.
    ///
    /// A component is allowed to have multiple relations, each one must be inserted into the mapping.
    ///
    /// # Example
    ///
    /// ```ignore
    /// stwo_prover::relation!(LookupElements, 2);
    /// stwo_prover::relation!(AdditionalLookupElements, 5);
    ///
    /// fn draw_lookup_elements(all_elements: &mut AllLookupElements, channel: &mut impl Channel, config: &ExtensionsConfig) {
    ///     all_elements.insert(LookupElements::draw(channel));
    ///     all_elements.insert(AdditionalLookupElements::draw(channel));
    /// }
    /// ```
    fn draw_lookup_elements(_: &mut AllLookupElements, _: &mut impl Channel, _: &ExtensionsConfig) {
    }
}

#[impl_for_tuples(1, 27)]
impl MachineChip for Tuple {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        config: &ExtensionsConfig,
    ) {
        for_tuples!( #( Tuple::fill_main_trace(traces, row_idx, vm_step, side_note, config); )* );
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
        config: &ExtensionsConfig,
    ) {
        for_tuples!( #( Tuple::add_constraints(eval, trace_eval, lookup_elements, config); )* );
    }

    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        program_traces: &ProgramTraces,
        lookup_elements: &AllLookupElements,
    ) {
        for_tuples!( #( Tuple::fill_interaction_trace(logup_trace_gen, original_traces, preprocessed_traces, program_traces, lookup_elements); )* );
    }

    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl Channel,
        config: &ExtensionsConfig,
    ) {
        for_tuples!( #( Tuple::draw_lookup_elements(all_elements, channel, config); )* );
    }
}

pub fn generate_interaction_trace<C: MachineChip>(
    original_traces: &FinalizedTraces,
    preprocessed_trace: &PreprocessedTraces,
    program_traces: &ProgramTraces,
    lookup_elements: &AllLookupElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    if lookup_elements.is_empty() {
        return (ColumnVec::new(), SecureField::zero());
    }
    let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());
    C::fill_interaction_trace(
        &mut logup_trace_gen,
        original_traces,
        preprocessed_trace,
        program_traces,
        lookup_elements,
    );
    logup_trace_gen.finalize_last()
}
