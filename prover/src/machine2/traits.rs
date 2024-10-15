use stwo_prover::constraint_framework::EvalAtRow;

use super::trace::{eval::TraceEval, Traces};

pub trait MachineChip {
    /// Called on each row during main trace generation.
    fn fill_main_trace(rd_idx: usize, traces: &mut Traces, row_idx: usize);

    /// Called on each row during constraint evaluation.
    ///
    /// This method **should not** read masks from `eval`.
    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>);
}
