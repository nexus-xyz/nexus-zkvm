use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::{component::ComponentTrace, eval::TraceEval};

use super::{Column, PreprocessedColumn, StoreOp};
use crate::lookups::{LogupTraceBuilder, RangeCheckLookupElements};

pub struct Sb;

impl StoreOp for Sb {
    const RAM2_ACCESSED: bool = false;
    const RAM3_4ACCESSED: bool = false;
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SB;
    const ALIGNMENT: u8 = 0;

    fn constrain_alignment<E: stwo_prover::constraint_framework::EvalAtRow>(
        _eval: &mut E,
        _trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        _range_check: &RangeCheckLookupElements,
    ) {
    }

    fn generate_interaction_trace(
        _logup_trace_builder: &mut LogupTraceBuilder,
        _component_trace: &ComponentTrace,
        _range_check: &RangeCheckLookupElements,
    ) {
    }
}
