use num_traits::One;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::eval::TraceEval;

use super::{BranchOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_b::{TypeB, TypeBDecoding};

pub struct BgeDecoding;
impl TypeBDecoding for BgeDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::BGE;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Bge = TypeB<BgeDecoding>;
impl BranchOp for Bge {
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [h_lt_flag] = trace_eval.column_eval(Column::HLtFlag);
        E::F::one() - h_lt_flag
    }
}
