use stwo_constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::eval::TraceEval;

use super::{BranchOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_b::{TypeB, TypeBDecoding};

pub struct BltuDecoding;
impl TypeBDecoding for BltuDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::BLTU;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Bltu = TypeB<BltuDecoding>;
impl BranchOp for Bltu {
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [_, h_borrow_2] = trace_eval.column_eval(Column::HBorrow);
        h_borrow_2
    }
}
