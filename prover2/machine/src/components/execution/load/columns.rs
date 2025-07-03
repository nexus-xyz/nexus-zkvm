use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

use crate::components::execution::decoding::{type_i, RegSplitAt0};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

/// Columns common to all load instructions.
///
/// Additional columns may be used depending on the memory read size and specific instruction semantics.
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

    // embedded type I decoding columns
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
    /// Bit 11 of op-c
    #[size = 1]
    OpC11,
    /// Lower 4 bits of op-c
    #[size = 1]
    OpC0_3,
    /// Bits 4–7 of op-c
    #[size = 1]
    OpC4_7,
    /// Bits 8–10 of op-c
    #[size = 1]
    OpC8_10,
}

pub const OP_A: RegSplitAt0<Column> = RegSplitAt0 {
    bit_0: Column::OpA0,
    bits_1_4: Column::OpA1_4,
};
pub const OP_B: RegSplitAt0<Column> = RegSplitAt0 {
    bit_0: Column::OpB0,
    bits_1_4: Column::OpB1_4,
};
pub const OP_C: type_i::OpC<Column> = type_i::OpC {
    op_c0_3: Column::OpC0_3,
    op_c4_7: Column::OpC4_7,
    op_c8_10: Column::OpC8_10,
    op_c11: Column::OpC11,
};

pub const fn load_instr_val(opcode: u8, funct3: u8) -> type_i::InstrVal<Column> {
    type_i::InstrVal {
        opcode,
        op_a0: Column::OpA0,
        op_a1_4: Column::OpA1_4,
        funct3,
        op_b0: Column::OpB0,
        op_b1_4: Column::OpB1_4,
        op_c0_3: Column::OpC0_3,
        op_c4_7: Column::OpC4_7,
        op_c8_10: Column::OpC8_10,
        op_c11: Column::OpC11,
    }
}
