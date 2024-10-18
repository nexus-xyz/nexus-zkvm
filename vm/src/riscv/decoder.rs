//! # Basic Block and Instruction Decoding for RISC-V
//!
//! This module provides robust functionality for decoding RISC-V instructions and organizing them into basic blocks,
//! which is essential for program analysis and optimization in RISC-V architectures.
//!
//! ## Basic Blocks
//!
//! A basic block is a fundamental concept in compiler design and program analysis. It represents a sequence of
//! instructions with the following properties:
//! - Entry point: The first instruction of the block, which is either the program's entry point or follows a branch/jump.
//! - Sequential execution: All instructions within the block are executed in order without any intermediate branches or jumps.
//! - Single exit point: The block ends with either a branch/jump instruction or the program's final instruction.
//!
//! ## Key Components
//!
//! - `BasicBlock`: Encapsulates a single basic block, containing a sequence of instructions.
//! - `BasicBlockProgram`: Represents a complete program as a collection of basic blocks.
//! - `Instruction`: Abstracts a single RISC-V instruction, encapsulating its opcode, operands, and functionality.
//! - `InstructionDecoder`: Provides utility methods for decoding raw instruction data into `Instruction` objects.
//!
//! ## Usage Example
//!
//! The following example demonstrates how to use this module to decode instructions from an ELF file:
//!
//! ```rust
//! use nexus_vm::riscv::decode_instructions;;
//! use nexus_vm::elf::ElfFile;
//!
//!
//! // Load an ELF file (implementation of load_elf_file is assumed)
//! let elf: ElfFile = ElfFile::from_path("test/helloworld.elf").expect("Failed to load ELF from path");
//!
//! // Decode instructions into a BasicBlockProgram
//! let program = decode_instructions(elf.instructions.as_ref());
//!
//! // Now you can analyze or process the basic blocks
//! for (i, block) in program.blocks.iter().enumerate() {
//!     println!("Basic Block {}:", i);
//!     for instruction in &block.0 {
//!         println!("  {}", instruction);
//!     }
//! }
//! ```
//!
//! This module is particularly useful for tasks such as control flow analysis, optimization,
//! and instruction-level parallelism detection in RISC-V programs.

use crate::riscv::instructions::{BasicBlock, BasicBlockProgram, Instruction, InstructionDecoder};
use nexus_common::riscv::{instruction::InstructionType, Opcode};
use rrs_lib::process_instruction;

/// Decodes RISC-V instructions from an ELF file into basic blocks
///
/// # Arguments
///
/// * `u32_instructions` - A slice of u32 values representing RISC-V instructions
///
/// # Returns
///
/// A `BasicBlockProgram` containing the decoded instructions organized into basic blocks
pub fn decode_instructions(u32_instructions: &[u32]) -> BasicBlockProgram {
    let mut program = BasicBlockProgram::default();
    let mut current_block = BasicBlock::default();
    let mut decoder = InstructionDecoder;
    let mut start_new_block = true;

    for &u32_instruction in u32_instructions.iter() {
        // Decode the instruction
        let decoded_instruction =
            process_instruction(&mut decoder, u32_instruction).unwrap_or_else(Instruction::unimp);

        // Start a new basic block if necessary
        if start_new_block && !current_block.0.is_empty() {
            program.blocks.push(current_block);
            current_block = BasicBlock::default();
        }

        // Check if the next instruction should start a new basic block
        start_new_block = decoded_instruction.is_branch_or_jump_instruction();

        // Add the decoded instruction to the current basic block
        current_block.0.push(decoded_instruction);
    }

    // Add the last block if it's not empty
    if !current_block.0.is_empty() {
        program.blocks.push(current_block);
    }

    program
}

#[inline(always)]
fn extract_opcode(u32_instruction: u32) -> u8 {
    const OPCODE_MASK: u32 = 0x7F; // 7 least significant bits (6-0)
    (u32_instruction & OPCODE_MASK) as u8
}

#[inline(always)]
fn extract_fn3(u32_instruction: u32) -> u8 {
    const FN3_MASK: u32 = 0x7000; // bits 14-12
    const FN3_SHIFT: u32 = 12;
    ((u32_instruction & FN3_MASK) >> FN3_SHIFT) as u8
}

#[inline(always)]
fn extract_fn7(u32_instruction: u32) -> u8 {
    const FN7_MASK: u32 = 0xFE000000; // 7 most significant bits (31-25)
    const FN7_SHIFT: u32 = 25;
    ((u32_instruction & FN7_MASK) >> FN7_SHIFT) as u8
}

#[inline(always)]
fn extract_rd(u32_instruction: u32) -> u8 {
    const RD_MASK: u32 = 0xF80; // bits 11-7
    const RD_SHIFT: u32 = 7;
    ((u32_instruction & RD_MASK) >> RD_SHIFT) as u8
}

#[inline(always)]
fn extract_rs1(u32_instruction: u32) -> u8 {
    const RS1_MASK: u32 = 0x000F8000; // bits 19-15
    const RS1_SHIFT: u32 = 15;
    ((u32_instruction & RS1_MASK) >> RS1_SHIFT) as u8
}

#[inline(always)]
fn extract_rs2(u32_instruction: u32) -> u8 {
    const RS2_MASK: u32 = 0x01F00000; // bits 24-20
    const RS2_SHIFT: u32 = 20;
    ((u32_instruction & RS2_MASK) >> RS2_SHIFT) as u8
}

const DYNAMIC_RTYPE_OPCODE: u8 = 0b0001011;

pub fn decode_until_end_of_a_block(u32_instructions: &[u32]) -> BasicBlock {
    let mut block = BasicBlock::default();
    let mut decoder = InstructionDecoder;

    for &u32_instruction in u32_instructions.iter() {
        // Decode the instruction
        let decoded_instruction = process_instruction(&mut decoder, u32_instruction)
            .unwrap_or_else(|| {
                // The rrs_lib instruction decoding doesn't have support for custom instructions,
                // so we need to handle them more as an error condition.
                let opcode = extract_opcode(u32_instruction);

                // Right now, we only support the single dynamic R-type opcode.
                if opcode != DYNAMIC_RTYPE_OPCODE {
                    return Instruction::unimp();
                }

                let fn3 = extract_fn3(u32_instruction);
                let fn7 = extract_fn7(u32_instruction);
                let rd = extract_rd(u32_instruction);
                let rs1 = extract_rs1(u32_instruction);
                let rs2 = extract_rs2(u32_instruction);

                let opcode = Opcode::new(opcode, Some(fn3), Some(fn7), "dynamic");

                Instruction::new(opcode, rd, rs1, rs2.into(), InstructionType::RType)
            });

        let pc_changed = decoded_instruction.is_branch_or_jump_instruction();

        block.0.push(decoded_instruction);

        if pc_changed {
            break;
        }
    }

    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfFile;
    use crate::elf::WORD_SIZE;

    /// Tests the decoding of instructions from an ELF file
    ///
    /// This test function does the following:
    /// 1. Defines test cases with file paths and entry points
    /// 2. Defines expected assembly output for comparison
    /// 3. Loads the ELF file for each test case
    /// 4. Decodes a subset of instructions starting from the entry point
    /// 5. Compares the decoded instructions with the expected assembly output
    #[test]
    fn test_decode_instruction_from_elf() {
        let test_cases = [("test/helloworld.elf", 0)];

        let gold_test = [
            "│   0: lw a1, sp, 16",
            "│   1: addi a2, sp, 36",
            "│   2: sw a2, 180(sp)",
            "│   3: lui a0, 0x2",
            "│   4: addi a0, a0, -1688",
            "│   5: sw a0, 184(sp)",
            "│   6: sw a2, 88(sp)",
            "│   7: sw a0, 92(sp)",
            "│   8: addi a3, sp, 32",
            "│   9: sw a3, 188(sp)",
            "│  10: lui a2, 0x1",
            "│  11: addi a2, a2, 1692",
            "│  12: sw a2, 192(sp)",
            "│  13: sw a3, 96(sp)",
            "│  14: sw a2, 100(sp)",
            "│  15: sw a1, 112(sp)",
            "│  16: addi a1, sp, 112",
            "│  17: sw a1, 196(sp)",
            "│  18: sw a0, 200(sp)",
            "│  19: sw a1, 104(sp)",
            "│  20: sw a0, 108(sp)",
            "│  21: lw a1, sp, 88",
            "│  22: lw a0, sp, 92",
            "│  23: sw a1, 64(sp)",
            "│  24: sw a0, 68(sp)",
            "│  25: lw a1, sp, 96",
            "│  26: lw a0, sp, 100",
            "│  27: sw a1, 72(sp)",
            "│  28: sw a0, 76(sp)",
            "│  29: lw a1, sp, 104",
            "│  30: lw a0, sp, 108",
            "│  31: sw a1, 80(sp)",
            "│  32: sw a0, 84(sp)",
            "│  33: lui a0, 0x3",
            "│  34: addi a1, a0, 1708",
            "│  35: addi a0, sp, 40",
            "│  36: sw a0, 8(sp)",
            "│  37: addi a3, sp, 64",
            "│  38: li a4, 3",
            "│  39: mv a2, a4",
            "│  40: auipc ra, 0x0",
            "│  41: jalr ra, ra, 556",
        ];

        for (file_path, entrypoint) in test_cases.iter() {
            let elf = ElfFile::from_path(file_path).expect("Unable to load ELF from path");
            assert_eq!(elf.entry, *entrypoint);
            let entry_instruction = (elf.entry - elf.base) / WORD_SIZE;
            let want_instructions = 200;
            let program = decode_instructions(
                &elf.instructions
                    [entry_instruction as usize..(entry_instruction + want_instructions) as usize],
            );

            for (asm, gold_asm) in program[29]
                .to_string()
                .split_terminator('\n')
                .zip(gold_test)
            {
                assert_eq!(asm, gold_asm);
            }
        }
    }

    #[test]
    fn test_decode_instruction_from_elf_until_end_of_block() {
        let test_cases = [("test/helloworld.elf", 0)];
        let gold_test = [
            "│   0: auipc gp, 0x4",
            "│   1: addi gp, gp, -496",
            "│   2: auipc sp, 0x400",
            "│   3: addi sp, sp, -12",
            "│   4: mv s0, sp",
            "│   5: jal ra, 0x0",
        ];
        for (file_path, entrypoint) in test_cases.iter() {
            let elf = ElfFile::from_path(file_path).expect("Unable to load ELF from path");
            assert_eq!(elf.entry, *entrypoint);
            let entry_instruction = (elf.entry - elf.base) / WORD_SIZE;
            let basic_block =
                decode_until_end_of_a_block(&elf.instructions[entry_instruction as usize..]);

            for (asm, gold_asm) in basic_block
                .to_string()
                .split_terminator('\n')
                .zip(gold_test)
            {
                assert_eq!(asm, gold_asm);
            }
        }
    }
}
