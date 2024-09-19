//! The Opcode were extract from this site: <https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf>

use std::fmt::Display;

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum Opcode {
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

    // Custom instruction placeholders
    // The Opcode enum is designed to be 1 byte for memory efficiency.
    // RISC-V 32IM uses 50 opcodes, leaving space for up to 206 custom instructions.
    // Custom instructions can be numbered from 0 to 205.
    CUSTOM0,
    CUSTOM1,
    CUSTOM2,
}

impl Opcode {
    fn mnemonic(&self) -> &'static str {
        match self {
            Opcode::ADD => "add",
            Opcode::SUB => "sub",
            Opcode::SLL => "sll",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            Opcode::XOR => "xor",
            Opcode::SRL => "srl",
            Opcode::SRA => "sra",
            Opcode::OR => "or",
            Opcode::AND => "and",

            Opcode::MUL => "mul",
            Opcode::MULH => "mulh",
            Opcode::MULHSU => "mulhsu",
            Opcode::MULHU => "mulhu",
            Opcode::DIV => "div",
            Opcode::DIVU => "divu",
            Opcode::REM => "rem",
            Opcode::REMU => "remu",

            Opcode::ADDI => "addi",
            Opcode::SLTI => "slti",
            Opcode::SLTIU => "sltiu",
            Opcode::XORI => "xori",
            Opcode::ORI => "ori",
            Opcode::ANDI => "andi",
            Opcode::SLLI => "slli",
            Opcode::SRLI => "srli",
            Opcode::SRAI => "srai",
            Opcode::LB => "lb",
            Opcode::LH => "lh",
            Opcode::LW => "lw",
            Opcode::LBU => "lbu",
            Opcode::LHU => "lhu",
            Opcode::JALR => "jalr",
            Opcode::ECALL => "ecall",
            Opcode::EBREAK => "ebreak",
            Opcode::FENCE => "fence",

            Opcode::SB => "sb",
            Opcode::SH => "sh",
            Opcode::SW => "sw",

            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BLT => "blt",
            Opcode::BGE => "bge",
            Opcode::BLTU => "bltu",
            Opcode::BGEU => "bgeu",

            Opcode::LUI => "lui",
            Opcode::AUIPC => "auipc",

            Opcode::JAL => "jal",

            Opcode::NOP => "nop",

            _ => "unimp",
        }
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_mnemonic() {
        assert_eq!(Opcode::ADD.mnemonic(), "add");
        assert_eq!(Opcode::SUB.mnemonic(), "sub");
        assert_eq!(Opcode::SLL.mnemonic(), "sll");
        assert_eq!(Opcode::MUL.mnemonic(), "mul");
        assert_eq!(Opcode::ADDI.mnemonic(), "addi");
        assert_eq!(Opcode::LB.mnemonic(), "lb");
        assert_eq!(Opcode::SB.mnemonic(), "sb");
        assert_eq!(Opcode::BEQ.mnemonic(), "beq");
        assert_eq!(Opcode::LUI.mnemonic(), "lui");
        assert_eq!(Opcode::JAL.mnemonic(), "jal");
        assert_eq!(Opcode::UNIMPL.mnemonic(), "unimp");
        assert_eq!(Opcode::CUSTOM0.mnemonic(), "unimp");
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(format!("{}", Opcode::ADD), "add");
        assert_eq!(format!("{}", Opcode::SUB), "sub");
        assert_eq!(format!("{}", Opcode::SLL), "sll");
        assert_eq!(format!("{}", Opcode::MUL), "mul");
        assert_eq!(format!("{}", Opcode::ADDI), "addi");
        assert_eq!(format!("{}", Opcode::LB), "lb");
        assert_eq!(format!("{}", Opcode::SB), "sb");
        assert_eq!(format!("{}", Opcode::BEQ), "beq");
        assert_eq!(format!("{}", Opcode::LUI), "lui");
        assert_eq!(format!("{}", Opcode::JAL), "jal");
        assert_eq!(format!("{}", Opcode::UNIMPL), "unimp");
        assert_eq!(format!("{}", Opcode::CUSTOM0), "unimp");
    }
}
