//! Abstract syntax of RV32 (based on RISC-V ISA V20191213)

mod display;
pub mod parse;

/// branch instruction type
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BOP {
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
}
pub use BOP::*;

/// load instruction type
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LOP {
    LB,
    LH,
    LW,
    LBU,
    LHU,
}
pub use LOP::*;

/// store instruction type
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SOP {
    SB,
    SH,
    SW,
}
pub use SOP::*;

/// ALU instruction type
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AOP {
    ADD,
    SUB,
    SLT,
    SLTU,
    SLL,
    SRL,
    SRA,
    OR,
    AND,
    XOR,
}
pub use AOP::*;

#[derive(Eq, Hash, PartialEq)]
pub enum InstructionSet {
    //
    RV32i,
    RV32Nexus,
}

/// RV32 instructions
#[rustfmt::skip]
#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub enum RV32 {
    LUI   { rd: u32, imm: u32, },
    AUIPC { rd: u32, imm: u32, },

    JAL  { rd: u32, imm: u32, },
    JALR { rd: u32, rs1: u32, imm: u32, },

    BR { bop: BOP, rs1: u32, rs2: u32, imm: u32, },

    LOAD  { lop: LOP, rd: u32, rs1: u32, imm: u32, },
    STORE { sop: SOP, rs1: u32, rs2: u32, imm: u32, },

    ALUI { aop: AOP, rd: u32, rs1: u32, imm: u32, },
    ALU  { aop: AOP, rd: u32, rs1: u32, rs2: u32, },

    FENCE,
    ECALL { rd: u32 },  // RV32Nexus Extension
    EBREAK { rd: u32 }, // RV32Nexus Extension

    #[default]
    UNIMP,
}
pub use RV32::*;

impl RV32 {
    pub fn rd(&self) -> Option<u32> {
        match *self {
            LUI { rd, .. } => Some(rd),
            AUIPC { rd, .. } => Some(rd),
            JAL { rd, .. } => Some(rd),
            JALR { rd, .. } => Some(rd),
            ALUI { rd, .. } => Some(rd),
            ALU { rd, .. } => Some(rd),
            LOAD { rd, .. } => Some(rd),
            _ => None,
        }
    }

    pub fn rs1(&self) -> Option<u32> {
        match *self {
            JALR { rs1, .. } => Some(rs1),
            BR { rs1, .. } => Some(rs1),
            LOAD { rs1, .. } => Some(rs1),
            STORE { rs1, .. } => Some(rs1),
            ALUI { rs1, .. } => Some(rs1),
            ALU { rs1, .. } => Some(rs1),
            _ => None,
        }
    }

    pub fn rs2(&self) -> Option<u32> {
        match *self {
            BR { rs2, .. } => Some(rs2),
            STORE { rs2, .. } => Some(rs2),
            ALU { rs2, .. } => Some(rs2),
            _ => None,
        }
    }

    pub fn imm(&self) -> Option<u32> {
        match *self {
            LUI { imm, .. } => Some(imm),
            AUIPC { imm, .. } => Some(imm),
            JAL { imm, .. } => Some(imm),
            JALR { imm, .. } => Some(imm),
            BR { imm, .. } => Some(imm),
            LOAD { imm, .. } => Some(imm),
            STORE { imm, .. } => Some(imm),
            ALUI { imm, .. } => Some(imm),
            _ => None,
        }
    }
}

/// a parsed RV32 instruction
#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Inst {
    /// program counter where instruction was found
    pub pc: u32,

    /// length of instruction in bytes
    pub len: u32,

    /// instruction as a 32-bit word
    pub word: u32,

    /// parsed instruction
    pub inst: RV32,
}

impl RV32 {
    /// maximum J value
    pub const MAX_J: u32 = 42;

    pub const fn instruction_set(&self) -> InstructionSet {
        match self {
            LUI { .. }
            | AUIPC { .. }
            | JAL { .. }
            | JALR { .. }
            | BR { .. }
            | LOAD { .. }
            | STORE { .. }
            | ALUI { .. }
            | ALU { .. }
            | FENCE
            | UNIMP => InstructionSet::RV32i,
            // we overload these instructions
            ECALL { .. } | EBREAK { .. } => InstructionSet::RV32Nexus,
        }
    }

    /// return the J index for instruction
    pub const fn index_j(&self) -> u32 {
        // It would be nice to use mem::variant_count here,
        // (and have fewer cases), but that is nightly rust only
        // Just list all cases so compiler will warn us if something
        // is added
        match self {
            LUI { .. } => 1,
            AUIPC { .. } => 2,
            JAL { .. } => 3,
            JALR { .. } => 4,

            //BR { bop, .. } => 5 + (bop as u32),
            BR { bop: BEQ, .. } => 5,
            BR { bop: BNE, .. } => 6,
            BR { bop: BLT, .. } => 7,
            BR { bop: BGE, .. } => 8,
            BR { bop: BLTU, .. } => 9,
            BR { bop: BGEU, .. } => 10,

            LOAD { lop: LB, .. } => 11,
            LOAD { lop: LH, .. } => 12,
            LOAD { lop: LW, .. } => 13,
            LOAD { lop: LBU, .. } => 14,
            LOAD { lop: LHU, .. } => 15,

            STORE { sop: SB, .. } => 16,
            STORE { sop: SH, .. } => 17,
            STORE { sop: SW, .. } => 18,

            ALUI { aop: ADD, .. } => 19,
            ALUI { aop: SUB, .. } => 20, // note: does not exist
            ALUI { aop: SLL, .. } => 21,
            ALUI { aop: SLT, .. } => 22,
            ALUI { aop: SLTU, .. } => 23,
            ALUI { aop: XOR, .. } => 24,
            ALUI { aop: SRL, .. } => 25,
            ALUI { aop: SRA, .. } => 26,
            ALUI { aop: OR, .. } => 27,
            ALUI { aop: AND, .. } => 28,

            ALU { aop: ADD, .. } => 29,
            ALU { aop: SUB, .. } => 30,
            ALU { aop: SLL, .. } => 31,
            ALU { aop: SLT, .. } => 32,
            ALU { aop: SLTU, .. } => 33,
            ALU { aop: XOR, .. } => 34,
            ALU { aop: SRL, .. } => 35,
            ALU { aop: SRA, .. } => 36,
            ALU { aop: OR, .. } => 37,
            ALU { aop: AND, .. } => 38,

            FENCE => 39,
            ECALL { .. } => 40,
            EBREAK { .. } => 41,
            UNIMP => 42,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_j() {
        assert!(RV32::UNIMP.index_j() == RV32::MAX_J);
    }
}
