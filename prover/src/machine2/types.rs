use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::utils::{ColumnNameItem, WORD_SIZE};

#[derive(Clone, Copy, Debug, EnumIter, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum RegisterMachineColumns {
    /// The current execution time.
    Clk,
    /// The current value of the program counter register.
    Pc,
    /// The opcode defining the instruction.
    Opcode,
    /// The address of the first operand of the instruction.
    OpA, // TODO (vlopes11) the first operand always receives the output of the operation.
    // Should it be a memory address?
    /// The address of the second operand of the instruction.
    OpB,
    /// The address of the third operand of the instruction.
    OpC,
    /// Additional columns for carrying limbs.
    CarryFlag,
    /// Is operand op_b an immediate value?
    ImmB, // TODO (vlopes11) is this needed?
    /// Is operand op_c an immediate value?
    ImmC,
    /// The actual 32-bit of the instruction stored at pc.
    Word,
    /// The previous counter for the instruction stored at pc.
    PrevCtr,
    /// The value of operand a.
    ValueA,
    /// The current timestamp for a.
    TsA,
    /// The previous value of operand a.
    PrevA,
    /// The previous timestamp for a.
    PrevTsA,
    /// The value of operand b.
    ValueB,
    /// The current timestamp for b.
    TsB,
    /// The previous value of operand b.
    PrevB,
    /// The previous timestamp for b.
    PrevTsB,
    /// The value of operand c.
    ValueC,
    /// The current timestamp for c.
    TsC,
    /// The previous value of operand c.
    PrevC,
    /// The previous timestamp for c.
    PrevTsC,
    /// Boolean flag on whether the row is an addition.
    IsAdd,
}

impl ColumnNameItem for RegisterMachineColumns {
    type Iter = RegisterMachineColumnsIter;

    fn items() -> Self::Iter {
        Self::iter()
    }

    fn size(&self) -> usize {
        match self {
            RegisterMachineColumns::Clk => WORD_SIZE,
            RegisterMachineColumns::Pc => WORD_SIZE,
            RegisterMachineColumns::Opcode => 1,
            RegisterMachineColumns::OpA => WORD_SIZE,
            RegisterMachineColumns::OpB => WORD_SIZE,
            RegisterMachineColumns::OpC => WORD_SIZE,
            RegisterMachineColumns::CarryFlag => WORD_SIZE,
            RegisterMachineColumns::ImmB => WORD_SIZE,
            RegisterMachineColumns::ImmC => WORD_SIZE,
            RegisterMachineColumns::Word => WORD_SIZE,
            RegisterMachineColumns::PrevCtr => WORD_SIZE,
            RegisterMachineColumns::ValueA => WORD_SIZE,
            RegisterMachineColumns::TsA => WORD_SIZE,
            RegisterMachineColumns::PrevA => WORD_SIZE,
            RegisterMachineColumns::PrevTsA => WORD_SIZE,
            RegisterMachineColumns::ValueB => WORD_SIZE,
            RegisterMachineColumns::TsB => WORD_SIZE,
            RegisterMachineColumns::PrevB => WORD_SIZE,
            RegisterMachineColumns::PrevTsB => WORD_SIZE,
            RegisterMachineColumns::ValueC => WORD_SIZE,
            RegisterMachineColumns::TsC => WORD_SIZE,
            RegisterMachineColumns::PrevC => WORD_SIZE,
            RegisterMachineColumns::PrevTsC => WORD_SIZE,
            RegisterMachineColumns::IsAdd => 1,
            // Avoid _ and let the compiler detect missing entries.
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Instruction {
    ADD,
}
