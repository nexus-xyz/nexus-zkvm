use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_air_column::empty::EmptyPreprocessedColumn;
use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{
    columns::{Column, PreprocessedColumn},
    BitwiseOp, XOR_LOOKUP_IDX,
};
use crate::components::execution::decoding::{type_i, type_r};

pub struct Xor;
impl BitwiseOp for Xor {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XOR;
    const REG2_ACCESSED: bool = true;
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;

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

pub struct XorI;
impl BitwiseOp for XorI {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XORI;
    const REG2_ACCESSED: bool = false;
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;

    type LocalColumn = type_i::DecodingColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
    ) {
        type_i::generate_trace_row(row_idx, trace, program_step);
    }

    fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let c_val = trace_eval!(trace_eval, Column::CVal);

        let [op_a0] = trace_eval!(local_trace_eval, type_i::DecodingColumn::OpA0);
        let [op_b0] = trace_eval!(local_trace_eval, type_i::DecodingColumn::OpB0);
        let [op_c11] = trace_eval!(local_trace_eval, type_i::DecodingColumn::OpC11);

        // constrain op_a0, op_b0, op_c11 ∈ {0, 1}
        for bit in [op_a0, op_b0, op_c11.clone()] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }

        type_i::constrain_c_val(eval, local_trace_eval, c_val, is_local_pad);
    }

    fn combine_reg_addresses<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) -> [E::F; 3] {
        let op_a = type_i::OP_A.eval(local_trace_eval);
        let op_b = type_i::OP_B.eval(local_trace_eval);
        let op_c = type_i::OP_C.eval(local_trace_eval);
        [op_a, op_b, op_c]
    }

    fn combine_instr_val<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) -> [E::F; nexus_vm::WORD_SIZE] {
        type_i::InstrVal::new(Self::OPCODE.raw(), Self::OPCODE.fn3().value()).eval(local_trace_eval)
    }
}
