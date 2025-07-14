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

use crate::components::execution::decoding::RegSplitAt4;

use super::{InstructionDecoding, RegSplitAt0};

/// Decoding columns used by type B instructions.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum DecodingColumn {
    /// Lower bit of op-a
    #[size = 1]
    OpA0,
    /// Higher 4 bits of op-a
    #[size = 1]
    OpA1_4,
    /// Lower 4 bits of op-b
    #[size = 1]
    OpB0_3,
    /// Bit 4 of op-b
    #[size = 1]
    OpB4,
    /// Bits 1 to 4 of op-c
    #[size = 1]
    OpC1_4,
    /// Bits 5 to 7 of op-c
    #[size = 1]
    OpC5_7,
    /// Bits 8 to 10 of op-c
    #[size = 1]
    OpC8_10,
    /// Bit 11 of op-c
    #[size = 1]
    OpC11,
    /// Bit 12 of op-c
    #[size = 1]
    OpC12,
}

pub const OP_A: RegSplitAt0<DecodingColumn> = RegSplitAt0 {
    bit_0: DecodingColumn::OpA0,
    bits_1_4: DecodingColumn::OpA1_4,
};
pub const OP_B: RegSplitAt4<DecodingColumn> = RegSplitAt4 {
    bits_0_3: DecodingColumn::OpB0_3,
    bit_4: DecodingColumn::OpB4,
};

pub struct CVal;

impl CVal {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_c1_4] = trace_eval.column_eval(DecodingColumn::OpC1_4);
        let [op_c5_7] = trace_eval.column_eval(DecodingColumn::OpC5_7);
        let [op_c8_10] = trace_eval.column_eval(DecodingColumn::OpC8_10);
        let [op_c11] = trace_eval.column_eval(DecodingColumn::OpC11);
        let [op_c12] = trace_eval.column_eval(DecodingColumn::OpC12);

        [
            op_c1_4 * BaseField::from(1 << 1) + op_c5_7 * BaseField::from(1 << 4),
            op_c8_10
                + op_c11 * BaseField::from(1 << 3)
                + op_c12.clone() * BaseField::from(((1 << 4) - 1) * (1 << 4)),
            op_c12.clone() * BaseField::from((1 << 8) - 1),
            op_c12 * BaseField::from((1 << 8) - 1),
        ]
    }
}

pub struct InstrVal {
    pub opcode: u8,
    pub funct3: u8,
}

impl InstrVal {
    pub fn new(opcode: u8, funct3: u8) -> Self {
        Self { opcode, funct3 }
    }

    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_a0] = trace_eval.column_eval(DecodingColumn::OpA0);
        let [op_a1_4] = trace_eval.column_eval(DecodingColumn::OpA1_4);

        let [op_b0_3] = trace_eval.column_eval(DecodingColumn::OpB0_3);
        let [op_b4] = trace_eval.column_eval(DecodingColumn::OpB4);

        let [op_c1_4] = trace_eval.column_eval(DecodingColumn::OpC1_4);
        let [op_c5_7] = trace_eval.column_eval(DecodingColumn::OpC5_7);
        let [op_c8_10] = trace_eval.column_eval(DecodingColumn::OpC8_10);
        let [op_c11] = trace_eval.column_eval(DecodingColumn::OpC11);
        let [op_c12] = trace_eval.column_eval(DecodingColumn::OpC12);

        let opcode = E::F::from(BaseField::from(self.opcode as u32));

        let instr_val_0 = opcode + op_c11 * BaseField::from(1 << 7);
        let instr_val_1 = op_c1_4
            + E::F::from(BaseField::from(self.funct3 as u32 * (1 << 4)))
            + op_a0 * BaseField::from(1 << 7);
        let instr_val_2 = op_a1_4 + op_b0_3 * BaseField::from(1 << 4);
        let instr_val_3 = op_b4
            + op_c5_7 * BaseField::from(1 << 1)
            + op_c8_10 * BaseField::from(1 << 4)
            + op_c12 * BaseField::from(1 << 7);

        [instr_val_0, instr_val_1, instr_val_2, instr_val_3]
    }
}

/// Splits registers addresses into parts and fills decoding columns.
pub fn generate_trace_row(
    row_idx: usize,
    trace: &mut TraceBuilder<DecodingColumn>,
    program_step: ProgramStep,
) {
    let op_c_raw = program_step.step.instruction.op_c;

    let op_c1_4 = ((op_c_raw >> 1) & 0b1111) as u8;
    let op_c5_7 = ((op_c_raw >> 5) & 0b111) as u8;
    let op_c8_10 = ((op_c_raw >> 8) & 0b111) as u8;
    let op_c11 = ((op_c_raw >> 11) & 0b1) as u8;
    let op_c12 = ((op_c_raw >> 12) & 0b1) as u8;

    trace.fill_columns(row_idx, op_c1_4, DecodingColumn::OpC1_4);
    trace.fill_columns(row_idx, op_c5_7, DecodingColumn::OpC5_7);
    trace.fill_columns(row_idx, op_c8_10, DecodingColumn::OpC8_10);
    trace.fill_columns(row_idx, op_c11, DecodingColumn::OpC11);
    trace.fill_columns(row_idx, op_c12, DecodingColumn::OpC12);

    let op_a_raw = program_step.step.instruction.op_a as u8;
    let op_a0 = op_a_raw & 0x1;
    let op_a1_4 = (op_a_raw >> 1) & 0b1111;

    trace.fill_columns(row_idx, op_a0, DecodingColumn::OpA0);
    trace.fill_columns(row_idx, op_a1_4, DecodingColumn::OpA1_4);

    let op_b_raw = program_step.step.instruction.op_b as u8;
    let op_b0_3 = op_b_raw & 0b1111;
    let op_b4 = (op_b_raw >> 4) & 0b1;
    trace.fill_columns(row_idx, op_b0_3, DecodingColumn::OpB0_3);
    trace.fill_columns(row_idx, op_b4, DecodingColumn::OpB4);
}

/// Zero-sized struct that implements type-U instruction decoding.
pub struct TypeB<T>(PhantomData<T>);

pub trait TypeBDecoding {
    const OPCODE: BuiltinOpcode;
    const IS_LOCAL_PAD: Self::MainColumn;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
}

impl<T: TypeBDecoding> InstructionDecoding for TypeB<T> {
    const OPCODE: BuiltinOpcode = T::OPCODE;
    const REG2_ACCESSED: bool = false;

    type PreprocessedColumn = <T as TypeBDecoding>::PreprocessedColumn;
    type MainColumn = <T as TypeBDecoding>::MainColumn;
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
        let [op_b4] = trace_eval!(decoding_trace_eval, DecodingColumn::OpB4);
        let [op_c11] = trace_eval!(decoding_trace_eval, DecodingColumn::OpB4);
        let [op_c12] = trace_eval!(decoding_trace_eval, DecodingColumn::OpB4);

        // constrain op_a0, op_b4, op_c11, op_c12 ∈ {0, 1}
        for bit in [op_a0, op_b4, op_c11, op_c12] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }
    }

    fn combine_reg_addresses<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; 3] {
        let op_a = OP_A.eval(decoding_trace_eval);
        let op_b = OP_B.eval(decoding_trace_eval);
        [op_a, op_b, E::F::zero()]
    }

    fn combine_instr_val<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        InstrVal::new(T::OPCODE.raw(), T::OPCODE.fn3().value()).eval(decoding_trace_eval)
    }
}
