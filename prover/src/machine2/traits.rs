use impl_trait_for_tuples::impl_for_tuples;
use stwo_prover::constraint_framework::EvalAtRow;

use super::trace::{eval::TraceEval, ProgramStep, Traces};

pub trait MachineChip {
    /// Called on each row during main trace generation.
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep);

    /// Called on each row during constraint evaluation.
    ///
    /// This method **should not** read masks from `eval`.
    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>);
}

#[impl_for_tuples(1, 12)]
impl MachineChip for Tuple {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        for_tuples!( #( Tuple::fill_main_trace(traces, row_idx, vm_step); )* );
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        for_tuples!( #( Tuple::add_constraints(eval, trace_eval); )* );
    }
}
