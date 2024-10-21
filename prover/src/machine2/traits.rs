use stwo_prover::constraint_framework::EvalAtRow;

use super::trace::{eval::TraceEval, Step, Traces};

pub(crate) trait MachineChip {
    /// Called on each row during main trace generation.
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &Step);

    /// Called on each row during constraint evaluation.
    ///
    /// This method **should not** read masks from `eval`.
    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>);
}
