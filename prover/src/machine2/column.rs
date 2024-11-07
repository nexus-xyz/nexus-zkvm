#![allow(clippy::assertions_on_constants)]

use nexus_vm_prover_macros::ColumnsEnum;

use crate::utils::WORD_SIZE;

const _: () = {
    // This assert is needed to prevent invalid definition of columns sizes.
    // If the size of a word changes, columns must be updated.
    assert!(WORD_SIZE == 4usize);
};

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, ColumnsEnum)]
pub enum Column {
    /// The current execution time.
    #[size = 4]
    Clk,
    /// The current value of the program counter register.
    #[size = 4]
    Pc,
    /// The opcode defining the instruction.
    #[size = 1]
    Opcode,

    // OP_A is the destination register, following RISC-V assembly syntax, e.g. ADD x1, x2, x3
    /// The register-index of the first operand of the instruction.
    #[size = 1]
    OpA,
    /// The register-index of the second operand of the instruction.
    #[size = 1]
    OpB,
    /// The register-index of the third operand of the instruction.
    #[size = 1]
    OpC,

    /// Additional columns for carrying limbs.
    #[size = 4]
    CarryFlag,
    /// Is operand op_b an immediate value?
    #[size = 1]
    ImmB,
    /// Is operand op_c an immediate value?
    #[size = 1]
    ImmC,
    /// The actual 32-bit of the instruction stored at pc.
    #[size = 4]
    Word,
    /// The previous counter for the instruction stored at pc.
    #[size = 4]
    PrevCtr,
    /// The value of operand a.
    #[size = 4]
    ValueA,
    /// The value of operand a to be written (zero if destination register index is zero).
    #[size = 4]
    ValueAEffective,
    /// The current timestamp for a.
    #[size = 4]
    TsA,
    /// The previous value of operand a.
    #[size = 4]
    PrevA,
    /// The previous timestamp for a.
    #[size = 4]
    PrevTsA,
    /// The value of operand b.
    #[size = 4]
    ValueB,
    /// The current timestamp for b.
    #[size = 4]
    TsB,
    /// The previous value of operand b.
    #[size = 4]
    PrevB,
    /// The previous timestamp for b.
    #[size = 4]
    PrevTsB,
    /// The value of operand c.
    #[size = 4]
    ValueC,
    /// The current timestamp for c.
    #[size = 4]
    TsC,
    /// The previous value of operand c.
    #[size = 4]
    PrevC,
    /// The previous timestamp for c.
    #[size = 4]
    PrevTsC,
    /// Boolean flag on whether the row is an addition.
    #[size = 1]
    IsAdd,
}

// proc macro derived:
//
// impl Column {
//     pub const COLUMNS_NUM: usize = /* ... */;
//     pub const fn size(self) -> usize { /* ... */ }
//     pub const fn offset(self) -> usize { /* ... */ }
// }
