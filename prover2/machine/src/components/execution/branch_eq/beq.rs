use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::eval::TraceEval;

use super::{BranchOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_b::{TypeB, TypeBDecoding};

pub struct BeqDecoding;
impl TypeBDecoding for BeqDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::BEQ;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Beq = TypeB<BeqDecoding>;
impl BranchOp for Beq {
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [h_neq_flag] = trace_eval.column_eval(Column::HNeqFlag);
        E::F::one() - h_neq_flag
    }
}
