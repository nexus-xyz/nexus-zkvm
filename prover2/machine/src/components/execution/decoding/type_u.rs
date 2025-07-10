use std::marker::PhantomData;

use num_traits::{One, Zero};
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{
    empty::EmptyPreprocessedColumn, AirColumn, PreprocessedAirColumn,
};
use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{InstructionDecoding, RegSplitAt0};

/// Decoding columns used by type U instructions.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum DecodingColumn {
    /// Lower bit of op-a
    #[size = 1]
    OpA0,
    /// Higher 4 bits of op-a
    #[size = 1]
    OpA1_4,
    /// Bit 11 of op-c
    #[size = 1]
    OpC12_15,
    /// Lower 4 bits of op-c
    #[size = 1]
    OpC16_23,
    /// Bits 4–7 of op-c
    #[size = 1]
    OpC24_31,
}

pub const OP_A: RegSplitAt0<DecodingColumn> = RegSplitAt0 {
    bit_0: DecodingColumn::OpA0,
    bits_1_4: DecodingColumn::OpA1_4,
};

pub struct CVal;

impl CVal {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_c12_15] = trace_eval.column_eval(DecodingColumn::OpC12_15);
        let [op_c16_23] = trace_eval.column_eval(DecodingColumn::OpC16_23);
        let [op_c24_31] = trace_eval.column_eval(DecodingColumn::OpC24_31);

        [
            E::F::zero(),
            op_c12_15 * BaseField::from(1 << 4),
            op_c16_23,
            op_c24_31,
        ]
    }
}

pub struct InstrVal {
    pub opcode: u8,
}

impl InstrVal {
    pub fn new(opcode: u8) -> Self {
        Self { opcode }
    }

    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_a0] = trace_eval.column_eval(DecodingColumn::OpA0);
        let [op_a1_4] = trace_eval.column_eval(DecodingColumn::OpA1_4);

        let [op_c12_15] = trace_eval.column_eval(DecodingColumn::OpC12_15);
        let [op_c16_23] = trace_eval.column_eval(DecodingColumn::OpC16_23);
        let [op_c24_31] = trace_eval.column_eval(DecodingColumn::OpC24_31);

        let opcode = E::F::from(BaseField::from(self.opcode as u32));

        let instr_val_0 = opcode + op_a0 * BaseField::from(1 << 7);
        let instr_val_1 = op_a1_4 + op_c12_15 * BaseField::from(1 << 4);
        let instr_val_2 = op_c16_23;
        let instr_val_3 = op_c24_31;

        [instr_val_0, instr_val_1, instr_val_2, instr_val_3]
    }
}

/// Splits registers addresses into parts and fills decoding columns.
pub fn generate_trace_row(
    row_idx: usize,
    trace: &mut TraceBuilder<DecodingColumn>,
    program_step: ProgramStep,
) {
    let op_a_raw = program_step.step.instruction.op_a as u8;
    let op_a0 = op_a_raw & 0x1;
    let op_a1_4 = (op_a_raw >> 1) & 0xF;
    trace.fill_columns(row_idx, op_a0, DecodingColumn::OpA0);
    trace.fill_columns(row_idx, op_a1_4, DecodingColumn::OpA1_4);

    let op_c_raw = program_step.step.instruction.op_c;
    let op_c12_15 = op_c_raw & 0xF;
    let op_c16_23 = (op_c_raw >> 4) & 0xFF;
    let op_c24_31 = (op_c_raw >> 12) & 0xFF;
    trace.fill_columns(row_idx, op_c12_15 as u8, DecodingColumn::OpC12_15);
    trace.fill_columns(row_idx, op_c16_23 as u8, DecodingColumn::OpC16_23);
    trace.fill_columns(row_idx, op_c24_31 as u8, DecodingColumn::OpC24_31);
}

/// Zero-sized struct that implements type-U instruction decoding.
pub struct TypeU<T>(PhantomData<T>);

pub trait TypeUDecoding {
    const OPCODE: BuiltinOpcode;
    const IS_LOCAL_PAD: Self::MainColumn;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
}

impl<T: TypeUDecoding> InstructionDecoding for TypeU<T> {
    const OPCODE: BuiltinOpcode = T::OPCODE;
    const REG2_ACCESSED: bool = false;

    type PreprocessedColumn = <T as TypeUDecoding>::PreprocessedColumn;
    type MainColumn = <T as TypeUDecoding>::MainColumn;
    type DecodingColumn = DecodingColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::DecodingColumn>,
        program_step: ProgramStep,
    ) {
        generate_trace_row(row_idx, trace, program_step);
    }

    fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        _trace_eval: &TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) {
        let [op_a0] = trace_eval!(decoding_trace_eval, DecodingColumn::OpA0);
        eval.add_constraint(op_a0.clone() * (E::F::one() - op_a0));
    }

    fn combine_reg_addresses<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; 3] {
        let op_a = OP_A.eval(decoding_trace_eval);
        [op_a, E::F::zero(), E::F::zero()]
    }

    fn combine_instr_val<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        InstrVal::new(T::OPCODE.raw()).eval(decoding_trace_eval)
    }
}
