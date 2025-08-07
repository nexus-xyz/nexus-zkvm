use num_traits::One;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::eval::TraceEval;

use super::{BranchOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_b::{TypeB, TypeBDecoding};

pub struct BgeuDecoding;
impl TypeBDecoding for BgeuDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::BGEU;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Bgeu = TypeB<BgeuDecoding>;
impl BranchOp for Bgeu {
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [_, h_borrow_2] = trace_eval.column_eval(Column::HBorrow);
        E::F::one() - h_borrow_2
    }
}
