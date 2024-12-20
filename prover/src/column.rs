#![allow(clippy::assertions_on_constants)]

use nexus_vm_prover_macros::ColumnsEnum;

use super::WORD_SIZE;

const _: () = {
    // This assert is needed to prevent invalid definition of columns sizes.
    // If the size of a word changes, columns must be updated.
    assert!(WORD_SIZE == 4usize);
};

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, ColumnsEnum)]
pub enum Column {
    /// The current value of the program counter register.
    #[size = 4]
    Pc,
    /// The next value of the program counter register.
    #[size = 4]
    PcNext,
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
    /// Subtraction columns for borrow limbs.
    #[size = 4]
    BorrowFlag,
    /// Is operand op_b an immediate value?
    #[size = 1]
    ImmB,
    /// Is operand op_c an immediate value?
    #[size = 1]
    ImmC,
    /// The actual 32-bit of the instruction stored at pc.
    #[size = 4]
    InstrVal,
    /// The previous counter for the instruction stored at pc.
    #[size = 4]
    PrevCtr,
    /// The value of operand a.
    #[size = 4]
    ValueA,
    /// The value of operand a to be written (zero if destination register index is zero).
    #[size = 4]
    ValueAEffective,
    /// The value of operand b.
    #[size = 4]
    ValueB,
    /// The value of operand c.
    #[size = 4]
    ValueC,

    // OPFLAGS
    /// Boolean flag on whether the row is an addition.
    #[size = 1]
    IsAdd,
    /// Boolean flag on whether the row is OR/ORI.
    #[size = 1]
    IsOr,
    /// Boolean flag on whether the row is AND/ANDI.
    #[size = 1]
    IsAnd,
    /// Boolean flag on whether the row is XOR/XORI.
    #[size = 1]
    IsXor,
    /// Boolean flag on whether the row is a subtraction.
    #[size = 1]
    IsSub,
    /// Boolean flag on whether the row is a SLTU.
    #[size = 1]
    IsSltu,
    /// Boolean flag on whether the row is a SLT.
    #[size = 1]
    IsSlt,
    /// Boolean flag on whether the row is a BNE.
    #[size = 1]
    IsBne,
    /// Boolean flag on whether the row is a BEQ.
    #[size = 1]
    IsBeq,
    /// Boolean flag on whether the row is a BLTU.
    #[size = 1]
    IsBltu,
    /// Boolean flag on whether the row is a BLT.
    #[size = 1]
    IsBlt,
    /// Boolean flag on whether the row is a BGEU.
    #[size = 1]
    IsBgeu,
    /// Boolean flag on whether the row is a BGE.
    #[size = 1]
    IsBge,
    /// Boolean flag on whether the row is a JAL.
    #[size = 1]
    IsJal,
    /// Boolean flag on whether the row is a SB
    #[size = 1]
    IsSb,
    /// Boolean flag on whether the row is a SH
    #[size = 1]
    IsSh,
    /// Boolean flag on whether the row is a SW
    #[size = 1]
    IsSw,
    /// Boolean flag on whether the row is a LB
    #[size = 1]
    IsLb,
    /// Boolean flag on whether the row is a LH
    #[size = 1]
    IsLh,
    /// Boolean flag on whether the row is a LW
    #[size = 1]
    IsLw,
    /// Boolean flag on whether the row is a padding.
    #[size = 1]
    IsPadding,

    /// Helper variable 1. Called h_1 in document.
    #[size = 4]
    Helper1,
    /// Helper variable 2. Called h_2 in document.
    #[size = 4]
    Helper2,
    /// Helper variable 3. Called h_3 in document.
    #[size = 4]
    Helper3,
    /// Signed bit of A.
    #[size = 1]
    SgnA,
    /// Signed bit of B.
    #[size = 1]
    SgnB,
    /// Signed bit of C.
    #[size = 1]
    SgnC,
    /// Negate flag. Called neq_flag in document.
    #[size = 1]
    Neq,
    /// Negate flag. Called neg_12_flag in document.
    #[size = 1]
    Neq12,
    /// Negate flag. Called neg_34_flag in document.
    #[size = 1]
    Neq34,
    /// Less than flag. Called lt_flag in document.
    #[size = 1]
    LtFlag,

    #[size = 1]
    Neq12Aux,
    #[size = 1]
    Neq34Aux,
    #[size = 1]
    Neq12AuxInv,
    #[size = 1]
    Neq34AuxInv,

    /// Multiplicity column for Range16Chip. Multiplicity16[row_idx] counts how many times the number row_idx is checked against Range16 in the entire trace.
    #[size = 1]
    Multiplicity16,
    /// Multiplicity column for Range32Chip. Multiplicity32[row_idx] counts how many times the number row_idx is checked against Range32 in the entire trace.
    #[size = 1]
    Multiplicity32,
    /// Multiplicity column for checking 0..=127. Multiplicity128[row_idx] counts how many times the number row_idx is checked in the entire trace.
    #[size = 1]
    Multiplicity128,
    /// Multiplicity column for byte range check. Multipllicity256[row_idx] counts how many times the number Range256[row_idx] is used in the entire trace.
    #[size = 1]
    Multiplicity256,
    /// Multiplicity column for bitwise-AND check. Multiplicity256[b * 256 + c] counts how many times (b & c) is looked up in the entire trace.
    #[size = 1]
    MultiplicityAnd,
    /// Multiplicity column for bitwise-OR check. Multiplicity256[b * 256 + c] counts how many times (b | c) is looked up in the entire trace.
    #[size = 1]
    MultiplicityOr,
    /// Multiplicity column for bitwise-XOR check. Multiplicity256[b * 256 + c] counts how many times (b ^ c) is looked up in the entire trace.
    #[size = 1]
    MultiplicityXor,
    /// 1 indicates OpA is non-zero, 0 indicates OpA is zero
    #[size = 1]
    ValueAEffectiveFlag,
    /// Auxiliary variable for computing ValueAEffectiveFlag
    #[size = 1]
    ValueAEffectiveFlagAux,
    /// Another auxiliary variable for computeing ValueAEffectiveFlag
    #[size = 1]
    ValueAEffectiveFlagAuxInv,

    /// Flag indicating register access slot 1 is used
    #[size = 1]
    Reg1Accessed,
    /// Flag indicating register access slot 2 is used
    #[size = 1]
    Reg2Accessed,
    /// Flag indicating register access slot 3 is used
    #[size = 1]
    Reg3Accessed,
    /// Register index of register access slot 1
    #[size = 1]
    Reg1Address,
    /// Register index of register access slot 2
    #[size = 1]
    Reg2Address,
    /// Register index of register access slot 3
    #[size = 1]
    Reg3Address,
    /// Previous value from the most recent access in Reg1Address
    #[size = 4]
    Reg1ValPrev,
    /// Previous value from the most recent access in Reg2Address
    #[size = 4]
    Reg2ValPrev,
    /// Previous value from the most recent access in Reg3Address
    #[size = 4]
    Reg3ValPrev,
    /// Previous timestamp from the most recent access in Reg1Address
    #[size = 4]
    Reg1TsPrev,
    /// Previous timestamp from the most recent access in Reg2Address
    #[size = 4]
    Reg2TsPrev,
    /// Previous timestamp from the most recent access in Reg3Address
    #[size = 4]
    Reg3TsPrev,
    /// On rows 0..32, contains the final value of 32 registers
    #[size = 4]
    FinalRegValue,
    /// On rows 0..32, contains the final timestamp of 32 registers
    #[size = 4]
    FinalRegTs,
    /// The last access counter of the program memory at Pc
    #[size = 4]
    ProgCtrPrev,
    /// The current access counter of the program memory at Pc, PrgPrevCtr + 1
    #[size = 4]
    ProgCtrCur,
    /// Carry flags for incrementing PrgPrevCtr into PrgCurCtr
    #[size = 4]
    ProgCtrCarry,
    /// Program memory content: final counter at PrgMemoryPc, filled after the execution
    #[size = 4]
    FinalPrgMemoryCtr,

    /// Aux variables for comparing previous and current timestamps
    #[size = 4]
    CReg1TsPrev,
    #[size = 4]
    CReg2TsPrev,
    #[size = 4]
    CReg3TsPrev,
    /// Aux borrow variables for comparing previous and current timestamps
    /// c_h1^-_1 in the design document
    #[size = 4]
    CH1Minus,
    /// c_h1^-_1 in the design document
    #[size = 4]
    CH2Minus,
    /// c_h1^-_1 in the design document
    #[size = 4]
    CH3Minus,

    /// The starting address of the read-write memory access
    #[size = 4]
    RamBaseAddr,
    /// The new value of the read-write memory at RamBaseAddr, if accessed
    #[size = 1]
    Ram1ValCur,
    /// The new value of the read-write memory at RamBaseAddr + 1, if accessed
    #[size = 1]
    Ram2ValCur,
    /// The new value of the read-write memory at RamBaseAddr + 2, if accessed
    #[size = 1]
    Ram3ValCur,
    /// The new value of the read-write memory at RamBaseAddr + 3, if accessed
    #[size = 1]
    Ram4ValCur,
    /// The previous value of the read-write memory at RamBaseAddr, if accessed
    #[size = 1]
    Ram1ValPrev,
    /// The previous value of the read-write memory at RamBaseAddr + 1, if accessed
    #[size = 1]
    Ram2ValPrev,
    /// The previous value of the read-write memory at RamBaseAddr + 2, if accessed
    #[size = 1]
    Ram3ValPrev,
    /// The previous value of the read-write memory at RamBaseAddr + 3, if accessed
    #[size = 1]
    Ram4ValPrev,
    /// The previous timestamp of the read-write memory at RamBaseAddr, if accessed
    #[size = 4]
    Ram1TsPrev,
    /// The previous timestamp of the read-write memory at RamBaseAddr + 1, if accessed
    #[size = 4]
    Ram2TsPrev,
    /// The previous timestamp of the read-write memory at RamBaseAddr + 2, if accessed
    #[size = 4]
    Ram3TsPrev,
    /// The previous timestamp of the read-write memory at RamBaseAddr + 3, if accessed
    #[size = 4]
    Ram4TsPrev,
    /// The flag indicating whether the read-write memory at RamBaseAddr is accessed
    #[size = 1]
    Ram1Accessed,
    /// The flag indicating whether the read-write memory at RamBaseAddr + 1 is accessed
    #[size = 1]
    Ram2Accessed,
    /// The flag indicating whether the read-write memory at RamBaseAddr + 2 is accessed
    #[size = 1]
    Ram3Accessed,
    /// The flag indicating whether the read-write memory at RamBaseAddr + 3 is accessed
    #[size = 1]
    Ram4Accessed,

    /// Auxiliary variable for decoding instruction: bits[0..=3] of OpC argument
    #[size = 1]
    OpC03,
    /// Auxiliary variable for decoding instruction: bits[1..=4] of OpA argument
    #[size = 1]
    OpA14,
    /// Auxiliary variable for decoding instruction: bits[1..=4] of OpB argument
    #[size = 1]
    OpB14,
    /// Auxiliary variable for decoding instruction: bits[4] of OpC argument
    #[size = 1]
    OpC4,
    /// Auxiliary variable for decoding instruction: bits[0] of OpA argument
    #[size = 1]
    OpA0,
    /// Auxiliary variable for decoding instruction: bits[0] of OpB argument
    #[size = 1]
    OpB0,
}

// proc macro derived:
//
// impl Column {
//     pub const COLUMNS_NUM: usize = /* ... */;
//     pub const fn size(self) -> usize { /* ... */ }
//     pub const fn offset(self) -> usize { /* ... */ }
// }

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, ColumnsEnum)]
pub enum ProgramColumn {
    /// Program memory content: every Pc in the program memory
    #[size = 4]
    PrgMemoryPc,
    /// Program memory content: Instruction word at PrgMemoryPc
    #[size = 4]
    PrgMemoryWord,
    /// Program memory content: 1 means the row contains real PrgMemory*. 0 otherwise.
    #[size = 1]
    PrgMemoryFlag,
    /// The first program counter for finding the first executed instruction
    #[size = 4]
    PrgInitialPc,
}

// proc macro derived:
//
// impl ProgramColumn {
//     pub const COLUMNS_NUM: usize = /* ... */;
//     pub const fn size(self) -> usize { /* ... */ }
//     pub const fn offset(self) -> usize { /* ... */ }
// }

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, ColumnsEnum)]
pub enum PreprocessedColumn {
    #[size = 1]
    IsFirst,
    /// One on the first 32 rows, then 0.
    #[size = 1]
    IsFirst32,
    /// Zero on the first row, then incremented by one per row
    #[size = 1]
    RowIdx,
    /// One on the first row, then incremented by one per row.
    #[size = 4]
    Clk,
    /// Timestamp for the first register access
    #[size = 4]
    Reg1TsCur,
    /// Timestamp for the second register access
    #[size = 4]
    Reg2TsCur,
    /// Timestamp for the third register access
    #[size = 4]
    Reg3TsCur,
    /// Contains numbers from 0 to 127, and 0 afterwards.
    #[size = 1]
    Range128,
    /// Contains numbers from 0 to 15, and 0 afterwards
    #[size = 1]
    Range16,
    /// Contains numbers from 0 to 7, and 0 afterwards
    #[size = 1]
    Range8,
    /// Contains numbers from 0 to 255, and 0 afterwards.
    #[size = 1]
    Range256,
    /// Contains numbers from 0 to 31, and 0 after wards
    #[size = 1]
    Range32,
    /// Contains numbers from 0 to 1023, and 0 afterwards
    #[size = 1]
    Range1024,
    /// Contains one-byte output of bit-wise AND
    #[size = 1]
    BitwiseAndByteA,
    /// Contains one-byte output of bit-wise OR
    #[size = 1]
    BitwiseOrByteA,
    /// Contains one-byte output of bit-wise XOR
    #[size = 1]
    BitwiseXorByteA,
    /// Contains one-byte first input of bit-wise lookup table
    #[size = 1]
    BitwiseByteB,
    /// Contains one-byte second input of bit-wise lookup table
    #[size = 1]
    BitwiseByteC,
}

// proc macro derived:
//
// impl PreprocessedColumn {
//     pub const COLUMNS_NUM: usize = /* ... */;
//     pub const fn size(self) -> usize { /* ... */ }
//     pub const fn offset(self) -> usize { /* ... */ }
// }
