use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_air_column::empty::EmptyPreprocessedColumn;
use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{Column, PreprocessedColumn, SltOp};

use crate::components::execution::decoding::type_r;

pub struct Slt;

impl SltOp for Slt {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLT;

    const REG2_ACCESSED: bool = true;

    type LocalColumn = type_r::DecodingColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
    ) {
        type_r::generate_trace_row(row_idx, trace, program_step);
    }

    fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        _trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) {
        let [op_a0] = trace_eval!(local_trace_eval, type_r::DecodingColumn::OpA0);
        let [op_b0] = trace_eval!(local_trace_eval, type_r::DecodingColumn::OpB0);
        let [op_c4] = trace_eval!(local_trace_eval, type_r::DecodingColumn::OpC4);

        // constrain op_a0, op_b0, op_c4 ∈ {0, 1}
        for bit in [op_a0, op_b0, op_c4] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }
    }

    fn combine_reg_addresses<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) -> [E::F; 3] {
        let op_a = type_r::OP_A.eval(local_trace_eval);
        let op_b = type_r::OP_B.eval(local_trace_eval);
        let op_c = type_r::OP_C.eval(local_trace_eval);
        [op_a, op_b, op_c]
    }

    fn combine_instr_val<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) -> [E::F; nexus_vm::WORD_SIZE] {
        type_r::InstrVal::new(
            Self::OPCODE.raw(),
            Self::OPCODE.fn3().value(),
            Self::OPCODE.fn7().value(),
        )
        .eval(local_trace_eval)
    }
}
