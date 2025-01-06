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

use crate::riscv::instructions::macros::{
    impl_b_type_instructions, impl_i_type_instructions, impl_i_type_shamt_instructions,
    impl_r_type_instructions, impl_s_type_instructions, impl_systemcall_instructions,
    impl_u_type_instructions, unimplemented_instructions,
};
use nexus_common::riscv::instruction::{Instruction, InstructionType};
use nexus_common::riscv::opcode::BuiltinOpcode;
use nexus_common::riscv::register::Register;
use nexus_common::riscv::Opcode;
use rrs_lib::instruction_formats::{
    BType, IType, ITypeCSR, ITypeShamt, JType, RType, SType, UType,
};
use rrs_lib::InstructionProcessor;

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
            Register::from(dec_insn.rd as u8),
            Register::from(0),
            dec_insn.imm as _,
            InstructionType::JType,
        )
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::from(BuiltinOpcode::JALR),
            Register::from(dec_insn.rd as u8),
            Register::from(dec_insn.rs1 as u8),
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
