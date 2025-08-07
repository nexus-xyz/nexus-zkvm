use stwo_constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::eval::TraceEval;

use super::{BranchOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_b::{TypeB, TypeBDecoding};

pub struct BneDecoding;
impl TypeBDecoding for BneDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::BNE;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Bne = TypeB<BneDecoding>;
impl BranchOp for Bne {
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [h_neq_flag] = trace_eval.column_eval(Column::HNeqFlag);
        h_neq_flag
    }
}
