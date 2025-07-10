use std::marker::PhantomData;

use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{
    empty::EmptyPreprocessedColumn, AirColumn, PreprocessedAirColumn,
};
use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{InstructionDecoding, RegSplitAt0, RegSplitAt4};

/// Decoding columns used by type I instructions.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum DecodingColumn {
    /// Lower bit of op-a
    #[size = 1]
    OpA0,
    /// Higher 4 bits of op-a
    #[size = 1]
    OpA1_4,
    /// Lower bit of op-b
    #[size = 1]
    OpB0,
    /// Higher 4 bits of op-b
    #[size = 1]
    OpB1_4,
    /// Highest bit of op-c
    #[size = 1]
    OpC4,
    /// Lower 4 bits of op-c
    #[size = 1]
    OpC0_3,
}

/// op-a register encoded as a linear combination of helper columns.
pub const OP_A: RegSplitAt0<DecodingColumn> = RegSplitAt0 {
    bit_0: DecodingColumn::OpA0,
    bits_1_4: DecodingColumn::OpA1_4,
};
/// op-b register encoded as a linear combination of helper columns.
pub const OP_B: RegSplitAt0<DecodingColumn> = RegSplitAt0 {
    bit_0: DecodingColumn::OpB0,
    bits_1_4: DecodingColumn::OpB1_4,
};
/// op-c register encoded as a linear combination of helper columns.
pub const OP_C: RegSplitAt4<DecodingColumn> = RegSplitAt4 {
    bits_0_3: DecodingColumn::OpC0_3,
    bit_4: DecodingColumn::OpC4,
};
pub struct InstrVal<C> {
    /// Byte 0: opcode + op_a0 * 2^7
    pub opcode: u8,
    pub op_a0: C,

    /// Byte 1: op_a1_4 + funct3 * 2^4 + op_b0 * 2^7
    pub op_a1_4: C,
    pub funct3: u8,
    pub op_b0: C,

    /// Byte 2: op_b1_4 + op_c0_3 * 2^4
    pub op_b1_4: C,
    pub op_c0_3: C,

    /// Byte 3: op_c4 + imm[11:5] * 2
    pub op_c4: C,
    pub funct7: u8,
}

impl InstrVal<DecodingColumn> {
    pub const fn new(opcode: u8, funct3: u8, funct7: u8) -> Self {
        Self {
            opcode,
            op_a0: DecodingColumn::OpA0,
            op_a1_4: DecodingColumn::OpA1_4,
            funct3,
            op_b0: DecodingColumn::OpB0,
            op_b1_4: DecodingColumn::OpB1_4,
            op_c0_3: DecodingColumn::OpC0_3,
            op_c4: DecodingColumn::OpC4,
            funct7,
        }
    }
}

impl<C: AirColumn> InstrVal<C> {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, C, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_a0] = trace_eval.column_eval(self.op_a0);
        let [op_a1_4] = trace_eval.column_eval(self.op_a1_4);
        let [op_b0] = trace_eval.column_eval(self.op_b0);
        let [op_b1_4] = trace_eval.column_eval(self.op_b1_4);
        let [op_c0_3] = trace_eval.column_eval(self.op_c0_3);
        let [op_c4] = trace_eval.column_eval(self.op_c4);

        let opcode = E::F::from(BaseField::from(self.opcode as u32));

        let instr_val_0 = opcode + op_a0 * BaseField::from(1 << 7);
        let instr_val_1 = op_a1_4
            + E::F::from(BaseField::from(self.funct3 as u32 * (1 << 4)))
            + op_b0 * BaseField::from(1 << 7);
        let instr_val_2 = op_b1_4 + op_c0_3 * BaseField::from(1 << 4);
        let instr_val_3 = op_c4 + E::F::from(BaseField::from(self.funct7 as u32 * 2));

        [instr_val_0, instr_val_1, instr_val_2, instr_val_3]
    }
}

/// Splits registers addresses and immediate into parts and fills decoding columns.
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

    let op_b_raw = program_step.step.instruction.op_b as u8;
    let op_b0 = op_b_raw & 0x1;
    let op_b1_4 = (op_b_raw >> 1) & 0xF;
    trace.fill_columns(row_idx, op_b0, DecodingColumn::OpB0);
    trace.fill_columns(row_idx, op_b1_4, DecodingColumn::OpB1_4);

    let op_c_raw = program_step.step.instruction.op_c as u8;
    let op_c0_3 = op_c_raw & 0xF;
    let op_c4 = (op_c_raw >> 4) & 0x1;
    trace.fill_columns(row_idx, op_c0_3, DecodingColumn::OpC0_3);
    trace.fill_columns(row_idx, op_c4, DecodingColumn::OpC4);
}

// Constrains c-val to equal 12-bit immediate
pub fn constrain_c_val<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<EmptyPreprocessedColumn, DecodingColumn, E>,
    c_val: [E::F; WORD_SIZE],
    is_local_pad: E::F,
) {
    let [op_c0_3] = trace_eval!(trace_eval, DecodingColumn::OpC0_3);
    let [op_c4] = trace_eval!(trace_eval, DecodingColumn::OpC4);

    // constrain c-val to equal 5-bit immediate
    //
    // (1 − is-local-pad) · (op-c0-3 + op-c4 · 2^4 − c-val(1)) = 0
    eval.add_constraint(
        (E::F::one() - is_local_pad.clone())
            * (op_c0_3.clone() + op_c4.clone() * BaseField::from(1 << 4) - c_val[0].clone()),
    );
    // (1 − is-local-pad) · (c-val(2) ) = 0
    // (1 − is-local-pad) · (c-val(3) ) = 0
    // (1 − is-local-pad) · (c-val(4) ) = 0
    for c_val_byte in &c_val[1..] {
        eval.add_constraint(c_val_byte.clone());
    }
}

/// Zero-sized struct that implements type-I shift instruction decoding.
pub struct TypeIShamt<T>(PhantomData<T>);

pub trait TypeIShamtDecoding {
    const OPCODE: BuiltinOpcode;
    const C_VAL: Self::MainColumn;
    const IS_LOCAL_PAD: Self::MainColumn;

    type PreprocessedColumn: PreprocessedAirColumn;
    type MainColumn: AirColumn;
}

impl<T: TypeIShamtDecoding> InstructionDecoding for TypeIShamt<T> {
    const OPCODE: BuiltinOpcode = T::OPCODE;
    const REG2_ACCESSED: bool = false;

    type PreprocessedColumn = <T as TypeIShamtDecoding>::PreprocessedColumn;
    type MainColumn = <T as TypeIShamtDecoding>::MainColumn;
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
        trace_eval: &TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) {
        let [is_local_pad] = trace_eval.column_eval(T::IS_LOCAL_PAD);
        let c_val = trace_eval.column_eval(T::C_VAL);

        let [op_a0] = trace_eval!(decoding_trace_eval, DecodingColumn::OpA0);
        let [op_b0] = trace_eval!(decoding_trace_eval, DecodingColumn::OpB0);
        let [op_c4] = trace_eval!(decoding_trace_eval, DecodingColumn::OpC4);

        // constrain op_a0, op_b0, op_c4 ∈ {0, 1}
        for bit in [op_a0, op_b0, op_c4] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }

        // TODO: move c-val to decoding
        constrain_c_val(eval, decoding_trace_eval, c_val, is_local_pad);
    }

    fn combine_reg_addresses<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; 3] {
        let op_a = OP_A.eval(decoding_trace_eval);
        let op_b = OP_B.eval(decoding_trace_eval);
        let op_c = OP_C.eval(decoding_trace_eval);
        [op_a, op_b, op_c]
    }

    fn combine_instr_val<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE] {
        InstrVal::new(
            T::OPCODE.raw(),
            T::OPCODE.fn3().value(),
            T::OPCODE.fn7().value(),
        )
        .eval(decoding_trace_eval)
    }
}
