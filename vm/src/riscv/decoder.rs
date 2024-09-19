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
//! let elf: ElfFile = ElfFile::from_path("test/pi.elf").expect("Failed to load ELF from path");
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

        // Add the decoded instruction to the current basic block
        current_block.0.push(decoded_instruction);

        // Check if the next instruction should start a new basic block
        start_new_block = decoded_instruction.is_branch_or_jump_instruction();
    }

    // Add the last block if it's not empty
    if !current_block.0.is_empty() {
        program.blocks.push(current_block);
    }

    program
}

pub fn decode_until_end_of_a_block(u32_instructions: &[u32]) -> BasicBlock {
    let mut block = BasicBlock::default();
    let mut decoder = InstructionDecoder;

    for &u32_instruction in u32_instructions.iter() {
        // Decode the instruction
        let decoded_instruction =
            process_instruction(&mut decoder, u32_instruction).unwrap_or_else(Instruction::unimp);

        block.0.push(decoded_instruction);

        if decoded_instruction.is_branch_or_jump_instruction() {
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
        let test_cases = [("test/pi.elf", 0x10164)];

        let gold_test = [
            "│   0: addi sp, sp, -16",
            "│   1: sw s0, 12(sp)",
            "│   2: mv a5, a0",
            "│   3: li t4, 1",
            "│   4: slli t5, a5, 8",
            "│   5: rem t5, t5, a2",
            "│   6: srai t1, a5, 8",
            "│   7: srai a0, t4, 8",
            "│   8: srai a7, t4, 16",
            "│   9: srai a6, a5, 16",
            "│  10: andi s0, t1, 255",
            "│  11: andi t3, a1, 1",
            "│  12: andi t2, t4, 255",
            "│  13: andi t6, a5, 255",
            "│  14: andi a0, a0, 255",
            "│  15: andi a7, a7, 255",
            "│  16: andi a6, a6, 255",
            "│  17: slli t1, t5, 8",
            "│  18: rem t1, t1, a2",
            "│  19: beq t3, zero, 0x4c",
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

            for (asm, gold_asm) in program[21]
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
        let test_cases = [("test/pi.elf", 0x10164)];
        let gold_test = [
            "│   0: auipc gp, 0x14",
            "│   1: addi gp, gp, 1708",
            "│   2: addi a0, gp, 48",
            "│   3: addi a2, gp, 1412",
            "│   4: sub a2, a2, a0",
            "│   5: li a1, 0",
            "│   6: jal ra, 0x0",
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
