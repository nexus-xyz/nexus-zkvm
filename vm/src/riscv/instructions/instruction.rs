//! This module defines the instruction types and decoding for RISC-V RV32IM instructions.
//!
//! It includes the `Instruction` struct, which represents a unified form for all instruction types,
//! and the `InstructionDecoder` struct, which implements the `InstructionProcessor` trait to decode
//! various RISC-V instruction formats.
//!
//! References:
//! - <https://github.com/riscv/riscv-opcodes/blob/master/rv32_i>
//! - <https://github.com/riscv/riscv-opcodes/blob/master/rv_i>
//! - <https://github.com/riscv/riscv-opcodes/blob/master/rv_m>

use std::fmt::Display;

use super::{BuiltinOpcode, Opcode};
use crate::riscv::instructions::macros::{
    impl_b_type_instructions, impl_i_type_instructions, impl_i_type_shamt_instructions,
    impl_r_type_instructions, impl_s_type_instructions, impl_systemcall_instructions,
    impl_u_type_instructions, unimplemented_instructions,
};
use crate::riscv::instructions::registers::Register;
use rrs_lib::instruction_formats::{
    BType, IType, ITypeCSR, ITypeShamt, JType, RType, SType, UType,
};
use rrs_lib::InstructionProcessor;

/// Represents all supported RISC-V RV32IM instruction types.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
    pub(crate) fn is_branch_or_jump_instruction(&self) -> bool {
        if let Ok(opcode) = self.opcode.try_into() {
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

    /// Creates a new instruction from an R-type instruction.
    fn from_r_type(opcode: Opcode, dec_insn: RType) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as _,
            dec_insn.rs1 as _,
            dec_insn.rs2 as _,
            InstructionType::RType,
        )
    }

    /// Creates a new instruction from an I-type instruction.
    fn from_i_type(opcode: Opcode, dec_insn: IType) -> Self {
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
    fn from_i_type_shamt(opcode: Opcode, dec_insn: ITypeShamt) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as _,
            dec_insn.rs1 as _,
            dec_insn.shamt as _,
            InstructionType::ITypeShamt,
        )
    }

    /// Creates a new instruction from an S-type instruction.
    fn from_s_type(opcode: Opcode, dec_insn: SType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs2 as _,
            dec_insn.rs1 as _,
            dec_insn.imm as _,
            InstructionType::SType,
        )
    }

    /// Creates a new instruction from a B-type instruction.
    fn from_b_type(opcode: Opcode, dec_insn: BType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs1 as _,
            dec_insn.rs2 as _,
            dec_insn.imm as _,
            InstructionType::BType,
        )
    }

    /// Creates a new unimplemented instruction.
    pub(crate) fn unimp() -> Self {
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
}

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // todo: handle not well-known opcodes
        assert!(self.opcode.is_builtin());

        let output = match self.ins_type {
            InstructionType::BType => self.b_type_to_string(self.opcode.try_into().unwrap()),
            InstructionType::IType | InstructionType::ITypeShamt => {
                self.i_type_to_string(self.opcode.try_into().unwrap())
            }
            InstructionType::JType => self.j_type_to_string(self.opcode.try_into().unwrap()),
            InstructionType::RType => self.r_type_to_string(self.opcode.try_into().unwrap()),
            InstructionType::SType => self.s_type_to_string(self.opcode.try_into().unwrap()),
            InstructionType::UType => self.u_type_to_string(self.opcode.try_into().unwrap()),
            InstructionType::Unimpl => self.opcode.to_string(),
        };

        f.write_str(&output)
    }
}

/// Struct responsible for decoding RISC-V instructions.
pub struct InstructionDecoder;

// Implementation of the InstructionProcessor trait for InstructionDecoder
impl InstructionProcessor for InstructionDecoder {
    type InstructionResult = Instruction;

    // Implementations for R-type instructions
    impl_r_type_instructions! {
        process_add => Opcode::from(BuiltinOpcode::ADD),
        process_sub => Opcode::from(BuiltinOpcode::SUB),
        process_sll => Opcode::from(BuiltinOpcode::SLL),
        process_slt => Opcode::from(BuiltinOpcode::SLT),
        process_sltu => Opcode::from(BuiltinOpcode::SLTU),
        process_xor => Opcode::from(BuiltinOpcode::XOR),
        process_srl => Opcode::from(BuiltinOpcode::SRL),
        process_sra => Opcode::from(BuiltinOpcode::SRA),
        process_or => Opcode::from(BuiltinOpcode::OR),
        process_and => Opcode::from(BuiltinOpcode::AND),
        process_mul => Opcode::from(BuiltinOpcode::MUL),
        process_mulh => Opcode::from(BuiltinOpcode::MULH),
        process_mulhsu => Opcode::from(BuiltinOpcode::MULHSU),
        process_mulhu => Opcode::from(BuiltinOpcode::MULHU),
        process_div => Opcode::from(BuiltinOpcode::DIV),
        process_divu => Opcode::from(BuiltinOpcode::DIVU),
        process_rem => Opcode::from(BuiltinOpcode::REM),
        process_remu => Opcode::from(BuiltinOpcode::REMU),
    }

    // Implementations for I-type instructions
    impl_i_type_instructions! {
        process_addi => Opcode::from(BuiltinOpcode::ADDI),
        process_slti => Opcode::from(BuiltinOpcode::SLTI),
        process_sltui => Opcode::from(BuiltinOpcode::SLTIU),
        process_xori => Opcode::from(BuiltinOpcode::XORI),
        process_ori => Opcode::from(BuiltinOpcode::ORI),
        process_andi => Opcode::from(BuiltinOpcode::ANDI),
        process_lb => Opcode::from(BuiltinOpcode::LB),
        process_lh => Opcode::from(BuiltinOpcode::LH),
        process_lw => Opcode::from(BuiltinOpcode::LW),
        process_lbu => Opcode::from(BuiltinOpcode::LBU),
        process_lhu => Opcode::from(BuiltinOpcode::LHU),
    }

    // Implementations for I-type instructions with shift amount
    impl_i_type_shamt_instructions! {
        process_slli => Opcode::from(BuiltinOpcode::SLLI),
        process_srli => Opcode::from(BuiltinOpcode::SRLI),
        process_srai => Opcode::from(BuiltinOpcode::SRAI),
    }

    // Implementations for system call instructions
    impl_systemcall_instructions! {
        process_ebreak => Opcode::from(BuiltinOpcode::EBREAK),
        process_ecall => Opcode::from(BuiltinOpcode::ECALL),
    }

    // Implementations for S-type instructions
    impl_s_type_instructions! {
        process_sb => Opcode::from(BuiltinOpcode::SB),
        process_sh => Opcode::from(BuiltinOpcode::SH),
        process_sw => Opcode::from(BuiltinOpcode::SW),
    }

    // Implementations for B-type instructions
    impl_b_type_instructions! {
        process_beq => Opcode::from(BuiltinOpcode::BEQ),
        process_bne => Opcode::from(BuiltinOpcode::BNE),
        process_blt => Opcode::from(BuiltinOpcode::BLT),
        process_bge => Opcode::from(BuiltinOpcode::BGE),
        process_bltu => Opcode::from(BuiltinOpcode::BLTU),
        process_bgeu => Opcode::from(BuiltinOpcode::BGEU),
    }

    // Implementations for U-type instructions
    impl_u_type_instructions! {
        process_lui => Opcode::from(BuiltinOpcode::LUI),
        process_auipc => Opcode::from(BuiltinOpcode::AUIPC),
    }

    // Implementations for J-type instructions
    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::from(BuiltinOpcode::JAL),
            dec_insn.rd as _,
            0,
            dec_insn.imm as _,
            InstructionType::JType,
        )
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::from(BuiltinOpcode::JALR),
            dec_insn.rd as _,
            dec_insn.rs1 as _,
            dec_insn.imm as _,
            InstructionType::IType,
        )
    }

    unimplemented_instructions! {
        process_csrrc(dec_insn: ITypeCSR),
        process_csrrci(dec_insn: ITypeCSR),
        process_csrrs(dec_insn: ITypeCSR),
        process_csrrsi(dec_insn: ITypeCSR),
        process_csrrw(dec_insn: ITypeCSR),
        process_csrrwi(dec_insn: ITypeCSR),
        process_fence(dec_insn: IType),
        process_mret(),
        process_wfi()
    }
}
