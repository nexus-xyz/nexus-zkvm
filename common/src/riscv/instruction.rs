use std::fmt::Display;

use crate::riscv::{encode_instruction, opcode::BuiltinOpcode};

use super::{register::Register, Opcode};

use rrs_lib::instruction_formats::{BType, IType, ITypeShamt, RType, SType};
use serde::{Deserialize, Serialize};

/// Represents all supported RISC-V RV32IM instruction types.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum InstructionType {
    RType,
    #[default]
    IType,
    ITypeShamt,
    SType,
    BType,
    UType,
    JType,
    Unimpl,
}

/// Represents a unified form for all RISC-V instructions.
///
/// This struct uses 8 bytes to store an instruction, keeping it as minimal as possible.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: Opcode,
    pub op_a: Register,
    pub op_b: Register,
    // Op_c can be either 12-bit immediate, 20-bit immediate, or a register index
    pub op_c: u32,
    pub ins_type: InstructionType,
}

impl Instruction {
    pub fn new(opcode: Opcode, op_a: u8, op_b: u8, op_c: u32, ins_type: InstructionType) -> Self {
        Self {
            opcode,
            op_a: Register::from(op_a),
            op_b: Register::from(op_b),
            op_c,
            ins_type,
        }
    }

    /// Returns true if the instruction is a branch or jump instruction.
    pub fn is_branch_or_jump_instruction(&self) -> bool {
        if let Some(opcode) = self.opcode.builtin() {
            matches!(
                opcode,
                BuiltinOpcode::BEQ
                    | BuiltinOpcode::BNE
                    | BuiltinOpcode::BLT
                    | BuiltinOpcode::BGE
                    | BuiltinOpcode::BLTU
                    | BuiltinOpcode::BGEU
                    | BuiltinOpcode::JAL
                    | BuiltinOpcode::JALR
            )
        } else {
            false
        }
    }

    // Returns true if the instruction is a system instruction
    pub fn is_system_instruction(&self) -> bool {
        if let Some(opcode) = self.opcode.builtin() {
            matches!(opcode, BuiltinOpcode::ECALL | BuiltinOpcode::EBREAK)
        } else {
            false
        }
    }

    /// Creates a new instruction from an R-type instruction.
    pub fn from_r_type(opcode: Opcode, dec_insn: RType) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as _,
            dec_insn.rs1 as _,
            dec_insn.rs2 as _,
            InstructionType::RType,
        )
    }

    /// Creates a new instruction from an I-type instruction.
    pub fn from_i_type(opcode: Opcode, dec_insn: IType) -> Self {
        let (rd, rs1, imm) = (dec_insn.rd as _, dec_insn.rs1 as _, dec_insn.imm as _);
        // Detect NOP instruction
        Self::new(
            if rd == 0 && rs1 == 0 && imm == 0 {
                Opcode::from(BuiltinOpcode::NOP)
            } else {
                opcode
            },
            rd,
            rs1,
            imm,
            InstructionType::IType,
        )
    }

    /// Creates a new instruction from an I-type instruction with a shift amount (shamt).
    pub fn from_i_type_shamt(opcode: Opcode, dec_insn: ITypeShamt) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as _,
            dec_insn.rs1 as _,
            dec_insn.shamt as _,
            InstructionType::ITypeShamt,
        )
    }

    /// Creates a new instruction from an S-type instruction.
    pub fn from_s_type(opcode: Opcode, dec_insn: SType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs2 as _,
            dec_insn.rs1 as _,
            dec_insn.imm as _,
            InstructionType::SType,
        )
    }

    /// Creates a new instruction from a B-type instruction.
    pub fn from_b_type(opcode: Opcode, dec_insn: BType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs1 as _,
            dec_insn.rs2 as _,
            dec_insn.imm as _,
            InstructionType::BType,
        )
    }

    /// Creates a new unimplemented instruction.
    /// When processing an unimplemented instruction, only the opcode is checked,
    /// and the fields op_a, op_b, and op_c are ignored.
    pub fn unimpl() -> Self {
        Self::new(
            Opcode::from(BuiltinOpcode::UNIMPL),
            0,
            0,
            0,
            InstructionType::Unimpl,
        )
    }

    // Helper methods for string representation of different instruction types
    fn r_type_to_string(&self, opcode: BuiltinOpcode) -> String {
        let rd = self.op_a;
        let rs1 = self.op_b;
        let rs2 = Register::from(self.op_c as u8);
        format!("{} {}, {}, {}", opcode, rd, rs1, rs2)
    }

    fn i_type_to_string(&self, opcode: BuiltinOpcode) -> String {
        let rd = self.op_a;
        let rs1 = self.op_b;
        let imm12 = self.op_c as i32;
        match opcode {
            BuiltinOpcode::NOP | BuiltinOpcode::EBREAK | BuiltinOpcode::ECALL => {
                self.opcode.to_string()
            }
            BuiltinOpcode::JALR => match (rd, rs1, imm12) {
                (Register::X0, Register::X1, 0) => "ret".to_string(),
                (Register::X0, _, 0) => format!("jr {}", rs1),
                (Register::X1, _, 0) => format!("{} {}", self.opcode, rs1),
                _ => format!("{} {}, {}, {}", opcode, rd, rs1, imm12),
            },
            BuiltinOpcode::JAL => match rd {
                Register::X0 => format!("j {}", imm12),
                Register::X1 => format!("{} {}", opcode, imm12),
                _ => format!("{} {}, {}, {}", opcode, rd, rs1, imm12),
            },
            BuiltinOpcode::ADDI => match (rs1, imm12) {
                (Register::X0, _) => format!("li {}, {}", rd, imm12),
                (_, 0) => format!("mv {}, {}", rd, rs1),
                _ => format!("{} {}, {}, {}", opcode, rd, rs1, imm12),
            },
            _ => format!("{} {}, {}, {}", opcode, rd, rs1, imm12),
        }
    }

    fn s_type_to_string(&self, opcode: BuiltinOpcode) -> String {
        let rs2 = self.op_a;
        let rs1 = self.op_b;
        let imm12 = self.op_c as i32;
        format!("{} {}, {}({})", opcode, rs2, imm12, rs1)
    }

    fn b_type_to_string(&self, opcode: BuiltinOpcode) -> String {
        let rs1 = self.op_a;
        let rs2 = self.op_b;
        let imm12 = self.op_c as i32;
        format!("{} {}, {}, 0x{:x}", opcode, rs1, rs2, imm12)
    }

    fn u_type_to_string(&self, opcode: BuiltinOpcode) -> String {
        let rd = self.op_a;
        let imm20 = self.op_c;
        format!("{} {}, 0x{:x}", opcode, rd, imm20)
    }

    fn j_type_to_string(&self, opcode: BuiltinOpcode) -> String {
        let rd = self.op_a;
        let imm20 = self.op_b as i32;
        format!("{} {}, 0x{:x}", opcode, rd, imm20)
    }

    // Encode the instruction struct to binary representation.
    pub fn encode(&self) -> u32 {
        encode_instruction(self)
    }
}

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = if self.opcode.is_builtin() {
            match self.ins_type {
                InstructionType::BType => self.b_type_to_string(self.opcode.builtin().unwrap()),
                InstructionType::IType | InstructionType::ITypeShamt => {
                    self.i_type_to_string(self.opcode.builtin().unwrap())
                }
                InstructionType::JType => self.j_type_to_string(self.opcode.builtin().unwrap()),
                InstructionType::RType => self.r_type_to_string(self.opcode.builtin().unwrap()),
                InstructionType::SType => self.s_type_to_string(self.opcode.builtin().unwrap()),
                InstructionType::UType => self.u_type_to_string(self.opcode.builtin().unwrap()),
                InstructionType::Unimpl => self.opcode.to_string(),
            }
        } else {
            self.opcode.to_string()
        };

        f.write_str(&output)
    }
}
