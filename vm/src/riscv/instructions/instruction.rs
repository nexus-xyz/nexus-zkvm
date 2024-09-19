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

use super::Opcode;
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
        matches!(
            self.opcode,
            Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU
                | Opcode::JAL
                | Opcode::JALR
        )
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
                Opcode::NOP
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
        Self::new(Opcode::UNIMPL, 0, 0, 0, InstructionType::Unimpl)
    }

    // Helper methods for string representation of different instruction types
    fn r_type_to_string(&self) -> String {
        let rd = self.op_a;
        let rs1 = self.op_b;
        let rs2 = Register::from(self.op_c as u8);
        format!("{} {}, {}, {}", self.opcode, rd, rs1, rs2)
    }

    fn i_type_to_string(&self) -> String {
        let rd = self.op_a;
        let rs1 = self.op_b;
        let imm12 = self.op_c as i32;
        match self.opcode {
            Opcode::NOP | Opcode::EBREAK | Opcode::ECALL => self.opcode.to_string(),
            Opcode::JALR => match (rd, rs1, imm12) {
                (Register::X0, Register::X1, 0) => "ret".to_string(),
                (Register::X0, _, 0) => format!("jr {}", rs1),
                (Register::X1, _, 0) => format!("{} {}", self.opcode, rs1),
                _ => format!("{} {}, {}, {}", self.opcode, rd, rs1, imm12),
            },
            Opcode::JAL => match rd {
                Register::X0 => format!("j {}", imm12),
                Register::X1 => format!("{} {}", self.opcode, imm12),
                _ => format!("{} {}, {}, {}", self.opcode, rd, rs1, imm12),
            },
            Opcode::ADDI => match (rs1, imm12) {
                (Register::X0, _) => format!("li {}, {}", rd, imm12),
                (_, 0) => format!("mv {}, {}", rd, rs1),
                _ => format!("{} {}, {}, {}", self.opcode, rd, rs1, imm12),
            },
            _ => format!("{} {}, {}, {}", self.opcode, rd, rs1, imm12),
        }
    }

    fn s_type_to_string(&self) -> String {
        let rs2 = self.op_a;
        let rs1 = self.op_b;
        let imm12 = self.op_c as i32;
        format!("{} {}, {}({})", self.opcode, rs2, imm12, rs1)
    }

    fn b_type_to_string(&self) -> String {
        let rs1 = self.op_a;
        let rs2 = self.op_b;
        let imm12 = self.op_c as i32;
        format!("{} {}, {}, 0x{:x}", self.opcode, rs1, rs2, imm12)
    }

    fn u_type_to_string(&self) -> String {
        let rd = self.op_a;
        let imm20 = self.op_c;
        format!("{} {}, 0x{:x}", self.opcode, rd, imm20)
    }

    fn j_type_to_string(&self) -> String {
        let rd = self.op_a;
        let imm20 = self.op_b as i32;
        format!("{} {}, 0x{:x}", self.opcode, rd, imm20)
    }
}

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self.ins_type {
            InstructionType::BType => self.b_type_to_string(),
            InstructionType::IType | InstructionType::ITypeShamt => self.i_type_to_string(),
            InstructionType::JType => self.j_type_to_string(),
            InstructionType::RType => self.r_type_to_string(),
            InstructionType::SType => self.s_type_to_string(),
            InstructionType::UType => self.u_type_to_string(),
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
        process_add => Opcode::ADD,
        process_sub => Opcode::SUB,
        process_sll => Opcode::SLL,
        process_slt => Opcode::SLT,
        process_sltu => Opcode::SLTU,
        process_xor => Opcode::XOR,
        process_srl => Opcode::SRL,
        process_sra => Opcode::SRA,
        process_or => Opcode::OR,
        process_and => Opcode::AND,
        process_mul => Opcode::MUL,
        process_mulh => Opcode::MULH,
        process_mulhsu => Opcode::MULHSU,
        process_mulhu => Opcode::MULHU,
        process_div => Opcode::DIV,
        process_divu => Opcode::DIVU,
        process_rem => Opcode::REM,
        process_remu => Opcode::REMU,
    }

    // Implementations for I-type instructions
    impl_i_type_instructions! {
        process_addi => Opcode::ADDI,
        process_slti => Opcode::SLTI,
        process_sltui => Opcode::SLTIU,
        process_xori => Opcode::XORI,
        process_ori => Opcode::ORI,
        process_andi => Opcode::ANDI,
        process_lb => Opcode::LB,
        process_lh => Opcode::LH,
        process_lw => Opcode::LW,
        process_lbu => Opcode::LBU,
        process_lhu => Opcode::LHU,
    }

    // Implementations for I-type instructions with shift amount
    impl_i_type_shamt_instructions! {
        process_slli => Opcode::SLLI,
        process_srli => Opcode::SRLI,
        process_srai => Opcode::SRAI,
    }

    // Implementations for system call instructions
    impl_systemcall_instructions! {
        process_ebreak => Opcode::EBREAK,
        process_ecall => Opcode::ECALL,
    }

    // Implementations for S-type instructions
    impl_s_type_instructions! {
        process_sb => Opcode::SB,
        process_sh => Opcode::SH,
        process_sw => Opcode::SW,
    }

    // Implementations for B-type instructions
    impl_b_type_instructions! {
        process_beq => Opcode::BEQ,
        process_bne => Opcode::BNE,
        process_blt => Opcode::BLT,
        process_bge => Opcode::BGE,
        process_bltu => Opcode::BLTU,
        process_bgeu => Opcode::BGEU,
    }

    // Implementations for U-type instructions
    impl_u_type_instructions! {
        process_lui => Opcode::LUI,
        process_auipc => Opcode::AUIPC,
    }

    // Implementations for J-type instructions
    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::JAL,
            dec_insn.rd as _,
            0,
            dec_insn.imm as _,
            InstructionType::JType,
        )
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::JALR,
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
