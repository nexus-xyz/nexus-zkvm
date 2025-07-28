//! # Basic Block and Instruction Encoder for RISC-V
//!
//! This module provides functionality for encoding RISC-V instructions into their little-endian binary representations.
//! It supports encoding various instruction types, including R-type, I-type, S-type, B-type, U-type, and J-type.
//!
//! ## Encoding an Instruction
//!
//! The `Instruction` struct implement an `encode` method that returns the binary representation
//! of the instruction as a `u32`. It supports encoding of built-in RISC-V instructions
//! based on their instruction type.
//!
//! ## Encoding a BasicBlock
//!
//! The `BasicBlock` struct implements an `encode` method that returns a `Vec<u32>` containing
//! the binary representations of the instructions in the block. It supports encoding
//! of built-in RISC-V instructions based on their instruction type.

use crate::{
    constants::KECCAKF_OPCODE,
    riscv::instruction::{Instruction, InstructionType},
};

/// Encodes an R-type instruction into its binary representation.
fn encode_r_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let rd = (instruction.op_a as u32 & 0x1F) << 7;
    let funct3 = (instruction.opcode.fn3.value() as u32) << 12;
    let rs1 = (instruction.op_b as u32 & 0x1F) << 15;
    let rs2 = (instruction.op_c & 0x1F) << 20;
    let funct7 = (instruction.opcode.fn7.value() as u32) << 25;

    opcode | rd | funct3 | rs1 | rs2 | funct7
}

/// Encodes an I-type instruction into its binary representation.
fn encode_i_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let rd = (instruction.op_a as u32 & 0x1F) << 7;
    let funct3 = (instruction.opcode.fn3.value() as u32) << 12;
    let rs1 = (instruction.op_b as u32 & 0x1F) << 15;
    let imm = (instruction.op_c & 0xFFF) << 20;

    opcode | rd | funct3 | rs1 | imm
}

/// Encodes an I-type instruction with shift amount (shamt) into its binary representation.
fn encode_i_shamt_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let rd = (instruction.op_a as u32 & 0x1F) << 7;
    let funct3 = (instruction.opcode.fn3.value() as u32) << 12;
    let rs1 = (instruction.op_b as u32 & 0x1F) << 15;
    let shamt = (instruction.op_c & 0x1F) << 20;
    let funct7 = (instruction.opcode.fn7.value() as u32) << 25;

    opcode | rd | funct3 | rs1 | shamt | funct7
}

/// Encodes an S-type instruction into its binary representation.
fn encode_s_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let funct3 = (instruction.opcode.fn3.value() as u32) << 12;
    let rs1 = (instruction.op_a as u32 & 0x1F) << 15;
    let rs2 = (instruction.op_b as u32 & 0x1F) << 20;
    let imm_4_0 = (instruction.op_c & 0x1F) << 7;
    let imm_11_5 = (instruction.op_c & 0xFE0) << 20;

    imm_11_5 | rs2 | rs1 | funct3 | imm_4_0 | opcode
}

/// Encodes a B-type instruction into its binary representation.
fn encode_b_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let funct3 = (instruction.opcode.fn3.value() as u32) << 12;
    let rs1 = (instruction.op_a as u32 & 0x1F) << 15;
    let rs2 = (instruction.op_b as u32 & 0x1F) << 20;
    let imm = instruction.op_c & 0x1FFE;
    let imm_11 = (imm & 0x800) >> 4;
    let imm_4_1 = (imm & 0x1E) << 7;
    let imm_10_5 = (imm & 0x7E0) << 20;
    let imm_12 = (imm & 0x1000) << 19;

    imm_12 | imm_10_5 | rs2 | rs1 | funct3 | imm_4_1 | imm_11 | opcode
}

/// Encodes a U-type instruction into its binary representation.
fn encode_u_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let rd = (instruction.op_a as u32 & 0x1F) << 7;
    let imm = (instruction.op_c << 12) & 0xFFFFF000;

    opcode | rd | imm
}

/// Encodes a J-type instruction into its binary representation.
fn encode_j_type(instruction: &Instruction) -> u32 {
    let opcode = (instruction.opcode.raw as u32) & 0x7F;
    let rd = (instruction.op_a as u32 & 0x1F) << 7;
    let imm = instruction.op_c as i32;

    // Reconstruct the immediate value in the correct bit positions
    let imm_20 = ((imm >> 20) & 1) << 31;
    let imm_10_1 = ((imm >> 1) & 0x3FF) << 21;
    let imm_11 = ((imm >> 11) & 1) << 20;
    let imm_19_12 = ((imm >> 12) & 0xFF) << 12;

    imm_20 as u32 | imm_10_1 as u32 | imm_11 as u32 | imm_19_12 as u32 | rd | opcode
}

/// Encodes an instruction into its binary representation to little-endian format.
///
/// Returns Ok(encoded_value) on success, or Err if the instruction is not supported.
///
/// This avoids panicking on unsupported custom opcodes, which is important for production
/// code that may receive untrusted or malformed input. Panics (assert!) are only for internal
/// invariants, not for external data validation.
pub fn encode_instruction(instruction: &Instruction) -> Result<u32, EncodeError> {
    if instruction.opcode.is_builtin() {
        let encoded = match instruction.ins_type {
            InstructionType::RType => encode_r_type(instruction).to_le(),
            InstructionType::IType => encode_i_type(instruction).to_le(),
            InstructionType::ITypeShamt => encode_i_shamt_type(instruction).to_le(),
            InstructionType::SType => encode_s_type(instruction).to_le(),
            InstructionType::BType => encode_b_type(instruction).to_le(),
            InstructionType::UType => encode_u_type(instruction).to_le(),
            InstructionType::JType => encode_j_type(instruction).to_le(),
            InstructionType::Unimpl => 0,
        };
        Ok(encoded)
    } else {
        if instruction.opcode.raw != KECCAKF_OPCODE {
            return Err(EncodeError::UnsupportedCustomOpcode(
                instruction.opcode.raw.into(),
            ));
        }
        Ok(encode_s_type(instruction).to_le())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    UnsupportedCustomOpcode(u32),
}

#[cfg(test)]
mod tests {
    use crate::riscv::{
        instruction::{Instruction, InstructionType},
        opcode::BuiltinOpcode,
        Opcode,
    };

    #[test]
    fn test_encode_simple_instructions() {
        // Test encoding of a simple R-type instruction
        let r_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::ADD),
            ins_type: InstructionType::RType,
            op_a: 2.into(),
            op_b: 3.into(),
            op_c: 1,
        };
        let encoded_r = r_instruction.encode();
        assert_eq!(encoded_r, 0x118133);

        // Test encode of a simple I-type instruction
        let i_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::ADDI),
            ins_type: InstructionType::IType,
            op_a: 2.into(),
            op_b: 3.into(),
            op_c: 10,
        };
        let encoded_i = i_instruction.encode();
        assert_eq!(encoded_i, 0xA18113);

        // Test encode of a simple S-type instruction
        let s_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::SW),
            ins_type: InstructionType::SType,
            op_a: 2.into(),
            op_b: 3.into(),
            op_c: 10,
        };
        let encoded_s = s_instruction.encode();
        assert_eq!(encoded_s, 0x312523);

        //  Test encode of a simple B-type instruction
        let b_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::BEQ),
            ins_type: InstructionType::BType,
            op_a: 2.into(),
            op_b: 3.into(),
            op_c: 10,
        };
        let encoded_b = b_instruction.encode();
        assert_eq!(encoded_b, 0x310563);

        //  Test encode of a simple U-type instruction
        let u_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::LUI),
            ins_type: InstructionType::UType,
            op_a: 2.into(),
            op_b: 0.into(),
            op_c: 10,
        };
        let encoded_u = u_instruction.encode();
        assert_eq!(encoded_u, 0xA137);

        //  Test encode of a simple J-type instruction
        let j_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::JAL),
            ins_type: InstructionType::JType,
            op_a: 2.into(),
            op_b: 0.into(),
            op_c: 10,
        };
        let encoded_j = j_instruction.encode();
        assert_eq!(encoded_j, 0xA0016F);

        //  Test encode of a simple I-type shamt instruction
        let i_shamt_instruction = Instruction {
            opcode: Opcode::from(BuiltinOpcode::SRAI),
            ins_type: InstructionType::ITypeShamt,
            op_a: 2.into(),
            op_b: 3.into(),
            op_c: 10,
        };
        let encoded_i_shamt = i_shamt_instruction.encode();
        assert_eq!(encoded_i_shamt, 0x40A1D113);
    }
}
