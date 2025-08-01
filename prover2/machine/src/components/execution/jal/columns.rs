use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::eval::TraceEval;

use crate::components::execution::decoding::RegSplitAt0;

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The helper bit to compute the next clock value
    #[size = 1]
    ClkCarry,
    /// A 32-bit word specifying the value of operand op-a represented by four 8-bit limbs
    #[size = 4]
    AVal,
    /// The current value of the program counter register
    #[size = 2]
    Pc,
    /// The helper bits to compute the program counter update
    #[size = 2]
    PcCarry,
    /// The next value of the program counter register after the execution
    #[size = 2]
    PcNext,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,
    /// Helper variables to implement the ADD functionality
    #[size = 2]
    HCarry,

    // embedded type J decoding columns
    /// Lower bit of op-a
    #[size = 1]
    OpA0,
    /// Higher 4 bits of op-a
    #[size = 1]
    OpA1_4,
    /// Bit 11 of op-c
    #[size = 1]
    OpC11,
    /// Bit 20 of op-c
    #[size = 1]
    OpC20,
    /// Bits 12 to 15 of op-c
    #[size = 1]
    OpC12_15,
    /// Bits 16 to 19 of op-c
    #[size = 1]
    OpC16_19,
    /// Bits 1 to 3 of op-c
    #[size = 1]
    OpC1_3,
    /// Bits 4 to 7 of op-c
    #[size = 1]
    OpC4_7,
    /// Bits 8 to 10 of op-c
    #[size = 1]
    OpC8_10,
}

pub const OP_A: RegSplitAt0<Column> = RegSplitAt0 {
    bit_0: Column::OpA0,
    bits_1_4: Column::OpA1_4,
};

pub struct CVal;

impl CVal {
    pub fn eval<E: EvalAtRow>(
        &self,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_c1_3] = trace_eval.column_eval(Column::OpC1_3);
        let [op_c4_7] = trace_eval.column_eval(Column::OpC4_7);
        let [op_c8_10] = trace_eval.column_eval(Column::OpC8_10);
        let [op_c11] = trace_eval.column_eval(Column::OpC11);
        let [op_c12_15] = trace_eval.column_eval(Column::OpC12_15);
        let [op_c16_19] = trace_eval.column_eval(Column::OpC16_19);
        let [op_c20] = trace_eval.column_eval(Column::OpC20);

        [
            op_c1_3 * BaseField::from(1 << 1) + op_c4_7 * BaseField::from(1 << 4),
            op_c8_10 + op_c11 * BaseField::from(1 << 3) + op_c12_15 * BaseField::from(1 << 4),
            op_c16_19 + op_c20.clone() * BaseField::from(((1 << 4) - 1) * (1 << 4)),
            op_c20 * BaseField::from((1 << 8) - 1),
        ]
    }
}

pub struct InstrVal;

impl InstrVal {
    pub fn eval<E: EvalAtRow>(
        &self,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_a0] = trace_eval.column_eval(Column::OpA0);
        let [op_a1_4] = trace_eval.column_eval(Column::OpA1_4);

        let [op_c1_3] = trace_eval.column_eval(Column::OpC1_3);
        let [op_c4_7] = trace_eval.column_eval(Column::OpC4_7);
        let [op_c8_10] = trace_eval.column_eval(Column::OpC8_10);
        let [op_c11] = trace_eval.column_eval(Column::OpC11);
        let [op_c12_15] = trace_eval.column_eval(Column::OpC12_15);
        let [op_c16_19] = trace_eval.column_eval(Column::OpC16_19);
        let [op_c20] = trace_eval.column_eval(Column::OpC20);

        let opcode = E::F::from(BaseField::from(BuiltinOpcode::JAL.raw() as u32));

        let instr_val_0 = opcode + op_a0 * BaseField::from(1 << 7);
        let instr_val_1 = op_a1_4 + op_c12_15 * BaseField::from(1 << 4);
        let instr_val_2 =
            op_c16_19 + op_c11 * BaseField::from(1 << 4) + op_c1_3 * BaseField::from(1 << 5);
        let instr_val_3 =
            op_c4_7 + op_c8_10 * BaseField::from(1 << 4) + op_c20 * BaseField::from(1 << 7);

        [instr_val_0, instr_val_1, instr_val_2, instr_val_3]
    }
}
