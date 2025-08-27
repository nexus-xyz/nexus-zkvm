//! The Opcode were extract from this site: <https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf>

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};
use variant_count::VariantCount;

use crate::error::OpcodeError;

use super::instruction::InstructionType;

/// `Opcode` does not directly correspond to an opcode as defined by RISC-V (which is the 7 least
/// significant bits of an instruction). Instead, it contains everything necessary to specify a
/// unique instruction, which may correspond to either a standard RISC-V instruction _or_ a custom
/// instruction.
///
/// The fn3 and fn7 fields are used to differentiate between different instructions with the same
/// RISC-V opcode.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
pub struct Opcode {
    /// The opcode as defined by RISC-V (7 least significant bits of an instruction). The MSB is
    /// always zero.
    pub raw: u8,

    /// The `funct3` field of the instruction, if applicable.
    pub fn3: SubByte<3>,

    /// The `funct7` field of the instruction, if applicable.
    pub fn7: SubByte<7>,

    /// The opcode's identifier - either a standard RISC-V opcode (BuiltinOpcode) or a custom
    /// instruction name.
    identifier: OpcodeIdentifier,
}

impl Opcode {
    const OPCODE_MASK: u8 = 0b0111_1111;

    /// Create a new, custom opcode with the given opcode, (optional) funct3/7 values, and name.
    /// Any non-custom opcode should be created using `Opcode::from` on a `BuiltinOpcode`.
    pub fn new<T: AsRef<str>>(opcode: u8, fn3: Option<u8>, fn7: Option<u8>, name: T) -> Self {
        let fn3 = fn3.map_or_else(SubByte::<3>::new_unset, SubByte::<3>::new_set);
        let fn7 = fn7.map_or_else(SubByte::<7>::new_unset, SubByte::<7>::new_set);

        Self {
            raw: opcode & Self::OPCODE_MASK,
            fn3,
            fn7,
            identifier: OpcodeIdentifier::Custom(name.as_ref().to_string()),
        }
    }

    pub fn is_builtin(&self) -> bool {
        matches!(self.identifier, OpcodeIdentifier::Builtin(_))
    }

    pub fn builtin(&self) -> Option<BuiltinOpcode> {
        match &self.identifier {
            OpcodeIdentifier::Builtin(builtin) => Some(*builtin),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        self.identifier.name()
    }

    pub fn raw(&self) -> u8 {
        self.raw
    }

    pub fn fn3(&self) -> SubByte<3> {
        self.fn3
    }

    pub fn fn7(&self) -> SubByte<7> {
        self.fn7
    }

    pub fn ins_type(&self) -> InstructionType {
        match &self.identifier {
            // For custom opcodes, infer the instruction type from the 7-bit opcode per design.
            // custom-0 => R-type (0b0001011)
            // custom-1 => I-type (0b0101011)
            // custom-2 => S-type (0b1011011)
            OpcodeIdentifier::Custom(_) => match self.raw() {
                0b0001011 => InstructionType::RType,
                0b0101011 => InstructionType::IType,
                0b1011011 => InstructionType::SType,
                _ => InstructionType::Unimpl,
            },
            _ => {
                if self.is_r_type() {
                    InstructionType::RType
                } else if self.is_i_type() {
                    InstructionType::IType
                } else if self.is_i_shamt_type() {
                    InstructionType::ITypeShamt
                } else if self.is_s_type() {
                    InstructionType::SType
                } else if self.is_b_type() {
                    InstructionType::BType
                } else if self.is_u_type() {
                    InstructionType::UType
                } else if self.is_j_type() {
                    InstructionType::JType
                } else if self.is_unimpl_type() {
                    InstructionType::Unimpl
                } else {
                    unreachable!("Opcodes should be one of the above types")
                }
            }
        }
    }

    fn is_r_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::ADD)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SUB)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SLL)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SLT)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SLTU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::XOR)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SRL)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SRA)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::OR)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::AND)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::MUL)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::MULH)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::MULHSU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::MULHU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::DIV)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::DIVU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::REM)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::REMU)
        )
    }

    fn is_i_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::ADDI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SLTI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SLTIU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::XORI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::ORI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::ANDI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::LB)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::LH)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::LW)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::LBU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::LHU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::JALR)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::ECALL)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::EBREAK)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::FENCE)
        )
    }

    fn is_i_shamt_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::SLLI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SRLI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SRAI)
        )
    }

    fn is_s_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::SB)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SH)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::SW)
        )
    }

    fn is_b_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::BEQ)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::BNE)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::BLT)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::BGE)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::BLTU)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::BGEU)
        )
    }

    fn is_u_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::LUI)
                | OpcodeIdentifier::Builtin(BuiltinOpcode::AUIPC)
        )
    }

    fn is_j_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::JAL)
        )
    }

    fn is_unimpl_type(&self) -> bool {
        matches!(
            self.identifier,
            OpcodeIdentifier::Builtin(BuiltinOpcode::UNIMPL)
        )
    }
}

impl From<BuiltinOpcode> for Opcode {
    fn from(opcode: BuiltinOpcode) -> Self {
        Self {
            raw: opcode.raw(),
            fn3: opcode.fn3(),
            fn7: opcode.fn7(),
            identifier: OpcodeIdentifier::Builtin(opcode),
        }
    }
}

impl TryInto<BuiltinOpcode> for Opcode {
    type Error = OpcodeError;

    fn try_into(self) -> Result<BuiltinOpcode, Self::Error> {
        match self.identifier {
            OpcodeIdentifier::Builtin(builtin) => Ok(builtin),
            _ => Err(Self::Error::OpcodeNotBuiltin(self)),
        }
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.identifier {
            OpcodeIdentifier::Custom(ref name) => f.write_fmt(format_args!(
                "{}: opcode={:#04X}, fn3={}, fn7={}",
                name, self.raw, self.fn3, self.fn7,
            )),
            _ => f.write_str(self.identifier.name()),
        }
    }
}

impl Default for Opcode {
    fn default() -> Self {
        Self {
            raw: 0,
            fn3: SubByte::<3>::new_unset(),
            fn7: SubByte::<7>::new_unset(),
            identifier: OpcodeIdentifier::None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
enum OpcodeIdentifier {
    Builtin(BuiltinOpcode),
    Custom(String),
    None,
}

impl OpcodeIdentifier {
    fn name(&self) -> &str {
        match self {
            OpcodeIdentifier::Builtin(builtin) => builtin.mnemonic(),
            OpcodeIdentifier::Custom(name) => name,
            OpcodeIdentifier::None => "None",
        }
    }
}

#[derive(
    Debug, Default, PartialEq, Eq, Clone, Copy, Hash, VariantCount, Serialize, Deserialize,
)]
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
    EBREAK, // Environment break       UNSUPPORTED
    FENCE,  // Fence (memory ordering) UNSUPPORTED

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

    // Placeholder for unimplemented instructions
    // UNIMPL instruction is used to represent instructions that are not yet implemented
    // or are intentionally left unimplemented in the current implementation.
    // In the RISC-V specification, this is similar to the UNIMP (unimplemented instruction) concept.
    // Note: This may be updated or replaced if CSR (Control and Status Register) instruction support is added in the future.
    #[default]
    UNIMPL,
}

impl BuiltinOpcode {
    const BUILTIN_NAMES: [&'static str; BuiltinOpcode::VARIANT_COUNT] = [
        "add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and", "mul", "mulh",
        "mulhsu", "mulhu", "div", "divu", "rem", "remu", "addi", "slli", "slti", "sltiu", "xori",
        "srli", "srai", "ori", "andi", "lb", "lh", "lw", "lbu", "lhu", "jalr", "ecall", "ebreak",
        "fence", "sb", "sh", "sw", "beq", "bne", "blt", "bge", "bltu", "bgeu", "lui", "auipc",
        "jal", "unimpl",
    ];

    fn mnemonic(&self) -> &'static str {
        // Safety: BUILTIN_NAMES is statically guaranteed to have the same size as the number of
        // variants for BuiltinOpcode.
        Self::BUILTIN_NAMES[*self as usize]
    }

    pub const fn raw(&self) -> u8 {
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

            BuiltinOpcode::UNIMPL => 0b000000,
        }
    }

    pub fn fn3(&self) -> SubByte<3> {
        match self {
            BuiltinOpcode::ADD | BuiltinOpcode::SUB => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::SLL => SubByte::<3>::new_set(0b001),
            BuiltinOpcode::SLT => SubByte::<3>::new_set(0b010),
            BuiltinOpcode::SLTU => SubByte::<3>::new_set(0b011),
            BuiltinOpcode::XOR => SubByte::<3>::new_set(0b100),
            BuiltinOpcode::SRL | BuiltinOpcode::SRA => SubByte::<3>::new_set(0b101),
            BuiltinOpcode::OR => SubByte::<3>::new_set(0b110),
            BuiltinOpcode::AND => SubByte::<3>::new_set(0b111),

            BuiltinOpcode::MUL => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::MULH => SubByte::<3>::new_set(0b001),
            BuiltinOpcode::MULHSU => SubByte::<3>::new_set(0b010),
            BuiltinOpcode::MULHU => SubByte::<3>::new_set(0b011),
            BuiltinOpcode::DIV => SubByte::<3>::new_set(0b100),
            BuiltinOpcode::DIVU => SubByte::<3>::new_set(0b101),
            BuiltinOpcode::REM => SubByte::<3>::new_set(0b110),
            BuiltinOpcode::REMU => SubByte::<3>::new_set(0b111),

            // n.b. nop is implemented as addi x0, x0, 0
            BuiltinOpcode::ADDI => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::SLTI => SubByte::<3>::new_set(0b010),
            BuiltinOpcode::SLTIU => SubByte::<3>::new_set(0b011),
            BuiltinOpcode::XORI => SubByte::<3>::new_set(0b100),
            BuiltinOpcode::ORI => SubByte::<3>::new_set(0b110),
            BuiltinOpcode::ANDI => SubByte::<3>::new_set(0b111),
            BuiltinOpcode::SLLI => SubByte::<3>::new_set(0b001),
            BuiltinOpcode::SRLI => SubByte::<3>::new_set(0b101),
            BuiltinOpcode::SRAI => SubByte::<3>::new_set(0b101),

            BuiltinOpcode::LB => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::LH => SubByte::<3>::new_set(0b001),
            BuiltinOpcode::LW => SubByte::<3>::new_set(0b010),
            BuiltinOpcode::LBU => SubByte::<3>::new_set(0b100),
            BuiltinOpcode::LHU => SubByte::<3>::new_set(0b101),
            BuiltinOpcode::SB => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::SH => SubByte::<3>::new_set(0b001),
            BuiltinOpcode::SW => SubByte::<3>::new_set(0b010),

            BuiltinOpcode::BEQ => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::BNE => SubByte::<3>::new_set(0b001),
            BuiltinOpcode::BLT => SubByte::<3>::new_set(0b100),
            BuiltinOpcode::BGE => SubByte::<3>::new_set(0b101),
            BuiltinOpcode::BLTU => SubByte::<3>::new_set(0b110),
            BuiltinOpcode::BGEU => SubByte::<3>::new_set(0b111),

            BuiltinOpcode::JALR => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::JAL => SubByte::<3>::new_unset(),

            BuiltinOpcode::LUI => SubByte::<3>::new_unset(),
            BuiltinOpcode::AUIPC => SubByte::<3>::new_unset(),

            BuiltinOpcode::ECALL => SubByte::<3>::new_set(0b000),
            BuiltinOpcode::EBREAK => SubByte::<3>::new_set(0b000),

            BuiltinOpcode::FENCE => SubByte::<3>::new_set(0b000),

            // Placeholder for unimplemented instructions should not have a known funct3
            BuiltinOpcode::UNIMPL => SubByte::<3>::new_unset(),
        }
    }

    pub fn fn7(&self) -> SubByte<7> {
        match self {
            BuiltinOpcode::ADD => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SUB => SubByte::<7>::new_set(0b0100000),
            BuiltinOpcode::SLL => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SLT => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SLTU => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::XOR => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SRL => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SRA => SubByte::<7>::new_set(0b0100000),
            BuiltinOpcode::OR => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::AND => SubByte::<7>::new_set(0b0000000),

            BuiltinOpcode::MUL => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::MULH => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::MULHSU => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::MULHU => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::DIV => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::DIVU => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::REM => SubByte::<7>::new_set(0b0000001),
            BuiltinOpcode::REMU => SubByte::<7>::new_set(0b0000001),

            // I-type instructions have no funct7.
            BuiltinOpcode::ADDI => SubByte::<7>::new_unset(),
            BuiltinOpcode::SLTI => SubByte::<7>::new_unset(),
            BuiltinOpcode::SLTIU => SubByte::<7>::new_unset(),
            BuiltinOpcode::XORI => SubByte::<7>::new_unset(),
            BuiltinOpcode::ORI => SubByte::<7>::new_unset(),
            BuiltinOpcode::ANDI => SubByte::<7>::new_unset(),

            // These are technically specified as imm[11:5] due to these instructions being I-type,
            // but they use the same bits as funct7, and for the same purpose, so it's most correct
            // to treat them as funct7 values here.
            BuiltinOpcode::SLLI => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SRLI => SubByte::<7>::new_set(0b0000000),
            BuiltinOpcode::SRAI => SubByte::<7>::new_set(0b0100000),

            // Memory operations are also I-type
            BuiltinOpcode::LB => SubByte::<7>::new_unset(),
            BuiltinOpcode::LH => SubByte::<7>::new_unset(),
            BuiltinOpcode::LW => SubByte::<7>::new_unset(),
            BuiltinOpcode::LBU => SubByte::<7>::new_unset(),
            BuiltinOpcode::LHU => SubByte::<7>::new_unset(),

            // S-type instructions have no funct7 either.
            BuiltinOpcode::SB => SubByte::<7>::new_unset(),
            BuiltinOpcode::SH => SubByte::<7>::new_unset(),
            BuiltinOpcode::SW => SubByte::<7>::new_unset(),

            // Same story for B-type, J-type, and U-type instructions, which all have larger
            // immediates instead of funct7 fields.
            BuiltinOpcode::BEQ => SubByte::<7>::new_unset(),
            BuiltinOpcode::BNE => SubByte::<7>::new_unset(),
            BuiltinOpcode::BLT => SubByte::<7>::new_unset(),
            BuiltinOpcode::BGE => SubByte::<7>::new_unset(),
            BuiltinOpcode::BLTU => SubByte::<7>::new_unset(),
            BuiltinOpcode::BGEU => SubByte::<7>::new_unset(),

            BuiltinOpcode::JALR => SubByte::<7>::new_unset(),
            BuiltinOpcode::JAL => SubByte::<7>::new_unset(),

            BuiltinOpcode::LUI => SubByte::<7>::new_unset(),
            BuiltinOpcode::AUIPC => SubByte::<7>::new_unset(),

            BuiltinOpcode::ECALL => SubByte::<7>::new_unset(),
            BuiltinOpcode::EBREAK => SubByte::<7>::new_unset(),

            BuiltinOpcode::FENCE => SubByte::<7>::new_unset(),

            BuiltinOpcode::UNIMPL => SubByte::<7>::new_unset(),
        }
    }
}

impl Display for BuiltinOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

/// Immutable type that behaves as Option<uX> where X is an integer in [1, 7]. Used for reasoning
/// about sub-byte values extracted from RISC-V instructions.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct SubByte<const BITS: u8> {
    value: u8,
}

impl<const BITS: u8> SubByte<BITS> {
    const SET_MASK: u8 = 0b1000_0000;
    const VALUE_MASK: u8 = (1u8 << BITS) - 1;

    /// Create a new OptionalUx with the value set to `value`, a la Option::Some(value).
    pub fn new_set(value: u8) -> Self {
        // This assert should evaluate statically to ensure proper use.
        assert!(BITS >= 1 && BITS <= 7);

        Self {
            value: (value & Self::VALUE_MASK) | Self::SET_MASK,
        }
    }

    /// Create a new OptionalUx with the value unset, a la Option::None.
    pub fn new_unset() -> Self {
        // Safety/correctness: the value being 0u8 is represented as 8 0 bits, which makes the most
        // significant bit 0, corresponding to the unset state.
        Self { value: 0 }
    }

    pub fn is_set(&self) -> bool {
        (self.value & Self::SET_MASK) != 0
    }

    pub fn value(&self) -> u8 {
        self.value & Self::VALUE_MASK
    }
}

impl<const BITS: u8> Display for SubByte<BITS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_set() {
            f.write_fmt(format_args!("Some({:#b})", self.value()))
        } else {
            f.write_str("None")
        }
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
        assert_eq!(BuiltinOpcode::UNIMPL.mnemonic(), "unimpl");
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
        assert_eq!(format!("{}", BuiltinOpcode::UNIMPL), "unimpl");
    }
}
