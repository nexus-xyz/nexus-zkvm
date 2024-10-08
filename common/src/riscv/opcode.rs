//! The Opcode were extract from this site: <https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf>

use std::fmt::Display;

use variant_count::VariantCount;

use crate::error::OpcodeError;

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Opcode {
    raw: u32,
    builtin: Option<BuiltinOpcode>,
    name: &'static str,
}

impl Opcode {
    pub fn new(opcode: u32, name: &'static str) -> Self {
        Self {
            raw: opcode,
            builtin: None,
            name,
        }
    }

    pub fn is_builtin(&self) -> bool {
        self.builtin.is_some()
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn raw(&self) -> u32 {
        self.raw
    }
}

impl From<BuiltinOpcode> for Opcode {
    fn from(opcode: BuiltinOpcode) -> Self {
        Self {
            raw: opcode.raw(),
            builtin: Some(opcode),
            name: opcode.mnemonic(),
        }
    }
}

impl TryInto<BuiltinOpcode> for Opcode {
    type Error = OpcodeError;

    fn try_into(self) -> Result<BuiltinOpcode, Self::Error> {
        if !self.is_builtin() {
            return Err(Self::Error::OpcodeNotBuiltin(self));
        }

        Ok(self.builtin.unwrap())
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Hash, VariantCount)]
#[allow(clippy::upper_case_acronyms)]
pub enum BuiltinOpcode {
    // R-type instructions
    ADD,  // Add
    SUB,  // Subtract
    SLL,  // Shift left logical
    SLT,  // Set less than
    SLTU, // Set less than unsigned
    XOR,  // Exclusive OR
    SRL,  // Shift right logical
    SRA,  // Shift right arithmetic
    OR,   // OR
    AND,  // AND

    // RISC-V M extension
    MUL,    // Multiply lower 32 bits of rs1 and rs2
    MULH,   // Multiply upper 32 bits of rs1 and rs2 (signed x signed)
    MULHSU, // Multiply upper 32 bits of rs1 and rs2 (signed x unsigned)
    MULHU,  // Multiply upper 32 bits of rs1 and rs2 (unsigned x unsigned)
    DIV,    // Divide rs1 by rs2 (signed)
    DIVU,   // Divide rs1 by rs2 (unsigned)
    REM,    // Remainder of rs1 divided by rs2 (signed)
    REMU,   // Remainder of rs1 divided by rs2 (unsigned)

    // I-type instructions
    ADDI,   // Add immediate
    SLLI,   // Shift left logical (immediate)
    SLTI,   // Set less than immediate
    SLTIU,  // Set less than immediate unsigned
    XORI,   // Exclusive OR immediate
    SRLI,   // Shift right logical (immediate)
    SRAI,   // Shift right arithmetic (immediate)
    ORI,    // OR immediate
    ANDI,   // AND immediate
    LB,     // Load byte
    LH,     // Load halfword
    LW,     // Load word
    LBU,    // Load byte unsigned
    LHU,    // Load halfword unsigned
    JALR,   // Jump and link register
    ECALL,  // Environment call
    EBREAK, // Environment break
    FENCE,  // Fence (memory ordering)

    // S-type instructions
    SB, // Store byte
    SH, // Store halfword
    SW, // Store word

    // B-type instructions
    BEQ,  // Branch if equal
    BNE,  // Branch if not equal
    BLT,  // Branch if less than
    BGE,  // Branch if greater than or equal
    BLTU, // Branch if less than unsigned
    BGEU, // Branch if greater than or equal unsigned

    // U-type instructions
    LUI,   // Load upper immediate
    AUIPC, // Add upper immediate to PC

    // J-type instructions
    JAL, // Jump and link

    // NOP instruction
    #[default]
    NOP,

    // Placeholder for unimplemented instructions
    UNIMPL,
}

impl BuiltinOpcode {
    fn mnemonic(&self) -> &'static str {
        match self {
            BuiltinOpcode::ADD => "add",
            BuiltinOpcode::SUB => "sub",
            BuiltinOpcode::SLL => "sll",
            BuiltinOpcode::SLT => "slt",
            BuiltinOpcode::SLTU => "sltu",
            BuiltinOpcode::XOR => "xor",
            BuiltinOpcode::SRL => "srl",
            BuiltinOpcode::SRA => "sra",
            BuiltinOpcode::OR => "or",
            BuiltinOpcode::AND => "and",

            BuiltinOpcode::MUL => "mul",
            BuiltinOpcode::MULH => "mulh",
            BuiltinOpcode::MULHSU => "mulhsu",
            BuiltinOpcode::MULHU => "mulhu",
            BuiltinOpcode::DIV => "div",
            BuiltinOpcode::DIVU => "divu",
            BuiltinOpcode::REM => "rem",
            BuiltinOpcode::REMU => "remu",

            BuiltinOpcode::ADDI => "addi",
            BuiltinOpcode::SLTI => "slti",
            BuiltinOpcode::SLTIU => "sltiu",
            BuiltinOpcode::XORI => "xori",
            BuiltinOpcode::ORI => "ori",
            BuiltinOpcode::ANDI => "andi",
            BuiltinOpcode::SLLI => "slli",
            BuiltinOpcode::SRLI => "srli",
            BuiltinOpcode::SRAI => "srai",
            BuiltinOpcode::LB => "lb",
            BuiltinOpcode::LH => "lh",
            BuiltinOpcode::LW => "lw",
            BuiltinOpcode::LBU => "lbu",
            BuiltinOpcode::LHU => "lhu",
            BuiltinOpcode::JALR => "jalr",
            BuiltinOpcode::ECALL => "ecall",
            BuiltinOpcode::EBREAK => "ebreak",
            BuiltinOpcode::FENCE => "fence",

            BuiltinOpcode::SB => "sb",
            BuiltinOpcode::SH => "sh",
            BuiltinOpcode::SW => "sw",

            BuiltinOpcode::BEQ => "beq",
            BuiltinOpcode::BNE => "bne",
            BuiltinOpcode::BLT => "blt",
            BuiltinOpcode::BGE => "bge",
            BuiltinOpcode::BLTU => "bltu",
            BuiltinOpcode::BGEU => "bgeu",

            BuiltinOpcode::LUI => "lui",
            BuiltinOpcode::AUIPC => "auipc",

            BuiltinOpcode::JAL => "jal",

            BuiltinOpcode::NOP => "nop",

            _ => "unimp",
        }
    }

    fn raw(&self) -> u32 {
        match self {
            BuiltinOpcode::ADD => 0b0110011,
            BuiltinOpcode::SUB => 0b0110011,
            BuiltinOpcode::SLL => 0b0110011,
            BuiltinOpcode::SLT => 0b0110011,
            BuiltinOpcode::SLTU => 0b0110011,
            BuiltinOpcode::XOR => 0b0110011,
            BuiltinOpcode::SRL => 0b0110011,
            BuiltinOpcode::SRA => 0b0110011,
            BuiltinOpcode::OR => 0b0110011,
            BuiltinOpcode::AND => 0b0110011,

            BuiltinOpcode::MUL => 0b0110011,
            BuiltinOpcode::MULH => 0b0110011,
            BuiltinOpcode::MULHSU => 0b0110011,
            BuiltinOpcode::MULHU => 0b0110011,
            BuiltinOpcode::DIV => 0b0110011,
            BuiltinOpcode::DIVU => 0b0110011,
            BuiltinOpcode::REM => 0b0110011,
            BuiltinOpcode::REMU => 0b0110011,

            BuiltinOpcode::ADDI => 0b0010011,
            BuiltinOpcode::SLTI => 0b0010011,
            BuiltinOpcode::SLTIU => 0b0010011,
            BuiltinOpcode::XORI => 0b0010011,
            BuiltinOpcode::ORI => 0b0010011,
            BuiltinOpcode::ANDI => 0b0010011,
            BuiltinOpcode::SLLI => 0b0010011,
            BuiltinOpcode::SRLI => 0b0010011,
            BuiltinOpcode::SRAI => 0b0010011,
            BuiltinOpcode::LB => 0b0000011,
            BuiltinOpcode::LH => 0b0000011,
            BuiltinOpcode::LW => 0b0000011,
            BuiltinOpcode::LBU => 0b0000011,
            BuiltinOpcode::LHU => 0b0000011,
            BuiltinOpcode::JALR => 0b1100111,
            BuiltinOpcode::ECALL => 0b1110011,
            BuiltinOpcode::EBREAK => 0b1110011,
            BuiltinOpcode::FENCE => 0b0001111,

            BuiltinOpcode::SB => 0b0100011,
            BuiltinOpcode::SH => 0b0100011,
            BuiltinOpcode::SW => 0b0100011,

            BuiltinOpcode::BEQ => 0b1100011,
            BuiltinOpcode::BNE => 0b1100011,
            BuiltinOpcode::BLT => 0b1100011,
            BuiltinOpcode::BGE => 0b1100011,
            BuiltinOpcode::BLTU => 0b1100011,
            BuiltinOpcode::BGEU => 0b1100011,

            BuiltinOpcode::LUI => 0b0110111,
            BuiltinOpcode::AUIPC => 0b0010111,

            BuiltinOpcode::JAL => 0b1101111,

            BuiltinOpcode::NOP => 0b0010011,

            _ => 0b000000,
        }
    }
}

impl Display for BuiltinOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_mnemonic() {
        assert_eq!(BuiltinOpcode::ADD.mnemonic(), "add");
        assert_eq!(BuiltinOpcode::SUB.mnemonic(), "sub");
        assert_eq!(BuiltinOpcode::SLL.mnemonic(), "sll");
        assert_eq!(BuiltinOpcode::MUL.mnemonic(), "mul");
        assert_eq!(BuiltinOpcode::ADDI.mnemonic(), "addi");
        assert_eq!(BuiltinOpcode::LB.mnemonic(), "lb");
        assert_eq!(BuiltinOpcode::SB.mnemonic(), "sb");
        assert_eq!(BuiltinOpcode::BEQ.mnemonic(), "beq");
        assert_eq!(BuiltinOpcode::LUI.mnemonic(), "lui");
        assert_eq!(BuiltinOpcode::JAL.mnemonic(), "jal");
        assert_eq!(BuiltinOpcode::UNIMPL.mnemonic(), "unimp");
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(format!("{}", BuiltinOpcode::ADD), "add");
        assert_eq!(format!("{}", BuiltinOpcode::SUB), "sub");
        assert_eq!(format!("{}", BuiltinOpcode::SLL), "sll");
        assert_eq!(format!("{}", BuiltinOpcode::MUL), "mul");
        assert_eq!(format!("{}", BuiltinOpcode::ADDI), "addi");
        assert_eq!(format!("{}", BuiltinOpcode::LB), "lb");
        assert_eq!(format!("{}", BuiltinOpcode::SB), "sb");
        assert_eq!(format!("{}", BuiltinOpcode::BEQ), "beq");
        assert_eq!(format!("{}", BuiltinOpcode::LUI), "lui");
        assert_eq!(format!("{}", BuiltinOpcode::JAL), "jal");
        assert_eq!(format!("{}", BuiltinOpcode::UNIMPL), "unimp");
    }
}
