use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::eval::TraceEval;

use super::{BranchOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_b::{TypeB, TypeBDecoding};

pub struct BltDecoding;
impl TypeBDecoding for BltDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::BLT;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Blt = TypeB<BltDecoding>;
impl BranchOp for Blt {
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [h_lt_flag] = trace_eval.column_eval(Column::HLtFlag);
        h_lt_flag
    }
}
