use nexus_vm::WORD_SIZE;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::eval::TraceEval;

use crate::components::execution::decoding::{RegSplitAt0, RegSplitAt4};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

/// Columns common to all store instructions.
///
/// Additional alignment column is used for SH and SW.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The next execution time represented by four 16-bit limbs
    #[size = 2]
    ClkNext,
    /// The helper bit to compute the next clock value
    #[size = 1]
    ClkCarry,
    /// A 32-bit word specifying the value of operand op-a represented by four 8-bit limbs
    #[size = 4]
    AVal,
    /// A 32-bit word specifying the value of operand op-b represented by four 8-bit limbs
    #[size = 4]
    BVal,
    /// A 32-bit word specifying the value of operand op-c represented by four 8-bit limbs
    #[size = 4]
    CVal,
    /// The current value of the program counter register
    #[size = 2]
    Pc,
    /// The helper bits to compute the program counter update
    #[size = 1]
    PcCarry,
    /// The next value of the program counter register after the execution
    #[size = 2]
    PcNext,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,
    /// Carry flags for computing load address
    #[size = 2]
    HCarry,
    /// Computed address of the load operation
    #[size = 4]
    HRamBaseAddr,

    // embedded type S decoding columns
    /// Lowest bit of op-a
    #[size = 1]
    OpA0,
    /// Higher 4 bits of op-a
    #[size = 1]
    OpA1_4,
    /// Highest bit of op-b
    #[size = 1]
    OpB4,
    /// Lower 4 bits of op-b
    #[size = 1]
    OpB0_3,
    /// Bit 0 of op-c.
    #[size = 1]
    OpC0,
    /// Bits 1 through 4 of op-c.
    #[size = 1]
    OpC1_4,
    /// Bits 5 through 7 of op-c.
    #[size = 1]
    OpC5_7,
    /// Bits 8 through 10 of op-c.
    #[size = 1]
    OpC8_10,
    /// Bit 11 of op-c.
    #[size = 1]
    OpC11,
}

pub const OP_A: RegSplitAt0<Column> = RegSplitAt0 {
    bit_0: Column::OpA0,
    bits_1_4: Column::OpA1_4,
};
pub const OP_B: RegSplitAt4<Column> = RegSplitAt4 {
    bits_0_3: Column::OpB0_3,
    bit_4: Column::OpB4,
};
pub const OP_C: OpC = OpC;

pub struct OpC;

impl OpC {
    pub fn eval<E: EvalAtRow>(
        &self,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F {
        let [op_c0] = trace_eval.column_eval(Column::OpC0);
        let [op_c1_4] = trace_eval.column_eval(Column::OpC1_4);
        let [op_c5_7] = trace_eval.column_eval(Column::OpC5_7);
        let [op_c8_10] = trace_eval.column_eval(Column::OpC8_10);
        let [op_c11] = trace_eval.column_eval(Column::OpC11);

        op_c0.clone()
            + op_c1_4.clone() * BaseField::from(2)
            + op_c5_7.clone() * BaseField::from(1 << 5)
            + op_c8_10.clone() * BaseField::from(1 << 8)
            + op_c11.clone() * BaseField::from(1 << 11)
    }
}

pub struct InstrVal {
    opcode: u8,
    funct3: u8,
}

impl InstrVal {
    pub const fn new(opcode: u8, funct3: u8) -> Self {
        Self { opcode, funct3 }
    }

    pub fn eval<E: EvalAtRow>(
        &self,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> [E::F; WORD_SIZE] {
        let [op_a0] = trace_eval.column_eval(Column::OpA0);
        let [op_a1_4] = trace_eval.column_eval(Column::OpA1_4);
        let [op_b0_3] = trace_eval.column_eval(Column::OpB0_3);
        let [op_b4] = trace_eval.column_eval(Column::OpB4);
        let [op_c0] = trace_eval.column_eval(Column::OpC0);
        let [op_c1_4] = trace_eval.column_eval(Column::OpC1_4);
        let [op_c5_7] = trace_eval.column_eval(Column::OpC5_7);
        let [op_c8_10] = trace_eval.column_eval(Column::OpC8_10);
        let [op_c11] = trace_eval.column_eval(Column::OpC11);

        let opcode = E::F::from(BaseField::from(self.opcode as u32));

        let instr_val_0 = opcode + op_c0 * BaseField::from(1 << 7);
        let instr_val_1 = op_c1_4
            + E::F::from(BaseField::from(self.funct3 as u32 * (1 << 4)))
            + op_a0 * BaseField::from(1 << 7);
        let instr_val_2 = op_a1_4 + op_b0_3 * BaseField::from(1 << 4);
        let instr_val_3 = op_b4
            + op_c5_7 * BaseField::from(1 << 1)
            + op_c8_10 * BaseField::from(1 << 4)
            + op_c11 * BaseField::from(1 << 7);

        [instr_val_0, instr_val_1, instr_val_2, instr_val_3]
    }
}
