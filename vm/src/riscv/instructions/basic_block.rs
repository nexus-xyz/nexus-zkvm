use std::{fmt::Display, ops::Index};

use super::Instruction;

/// Represents a basic block of RISC-V instructions
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock(pub Vec<Instruction>);

impl Display for BasicBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (j, instruction) in self.0.iter().enumerate() {
            writeln!(f, "│ {:3}: {}", j, instruction)?;
        }

        Ok(())
    }
}

impl BasicBlock {
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self(instructions)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn print_with_offset(&self, offset: usize) {
        println!("┌─────────────────────────────────────────────────");
        for (j, instruction) in self.0.iter().enumerate() {
            println!("│ {:3}: {}", j * 4 + offset, instruction);
        }
        println!("└─────────────────────────────────────────────────");
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Encodes a basic block of RISC-V instructions into their binary representations.
    ///
    /// This function takes a reference to a `BasicBlock` and returns a vector of `u32`,
    /// where each `u32` represents the binary encoding of an instruction in the block.
    pub fn encode(&self) -> Vec<u32> {
        self.0
            .iter()
            .map(|instruction| instruction.encode())
            .collect()
    }
}

impl Index<usize> for BasicBlock {
    type Output = Instruction;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// Represents the entire program as a collection of basic blocks
#[derive(Default)]
pub struct BasicBlockProgram {
    pub blocks: Vec<BasicBlock>,
}

impl BasicBlockProgram {
    pub fn blocks_len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.blocks.iter().map(|block| block.len()).sum()
    }
}

impl Index<usize> for BasicBlockProgram {
    type Output = BasicBlock;
    fn index(&self, index: usize) -> &Self::Output {
        &self.blocks[index]
    }
}

impl Display for BasicBlockProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, block) in self.blocks.iter().enumerate() {
            writeln!(f, "┌─────────────────────────────────────────────────")?;
            writeln!(f, "│ Basic Block {:3}", i)?;
            writeln!(f, "├─────────────────────────────────────────────────")?;
            write!(f, "{}", block)?;
            writeln!(f, "└─────────────────────────────────────────────────")?;
            writeln!(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::elf::ElfFile;
    use crate::riscv::{decode_instructions, decode_until_end_of_a_block};
    use crate::WORD_SIZE;

    #[test]
    fn test_encode_decode_consistency_in_a_block() {
        let file_path = "test/helloworld.elf";
        let elf = ElfFile::from_path(file_path).expect("Unable to load ELF from path");

        // Get the entry point and calculate the instruction index
        let entry_instruction = (elf.entry - elf.base) / WORD_SIZE as u32;

        // Decode a block of instructions
        let original_block =
            decode_until_end_of_a_block(&elf.instructions[entry_instruction as usize..]);

        // Encode the decoded instructions
        let encoded_instructions: Vec<u32> = original_block.encode();

        // Make sure the encoded_instructions is as same as the 32-bit little-endian instructions in the ELF file.
        assert_eq!(
            0,
            encoded_instructions
                .iter()
                .zip(&elf.instructions[entry_instruction as usize..])
                .filter(|(a, b)| a != b)
                .count()
        );

        // Decode the encoded instructions
        let re_decoded_block = decode_until_end_of_a_block(&encoded_instructions);

        // Compare the original and re-decoded blocks
        assert_eq!(
            original_block.len(),
            re_decoded_block.len(),
            "Number of instructions mismatch"
        );

        for (original, re_decoded) in original_block.0.iter().zip(re_decoded_block.0.iter()) {
            assert_eq!(
                original, re_decoded,
                "Instruction mismatch:\nOriginal: {}\nRe-decoded: {}",
                original, re_decoded
            );
        }
    }

    #[test]
    fn test_encode_decode_consistency_from_elf() {
        let file_path = "test/helloworld.elf";
        let elf = ElfFile::from_path(file_path).expect("Unable to load ELF from path");

        // Get the entry point and calculate the instruction index
        let entry_instruction = (elf.entry - elf.base) / WORD_SIZE as u32;

        // Define the number of instructions to test
        let num_instructions = 200;

        // Decode a larger portion of the ELF file
        let original_program = decode_instructions(
            &elf.instructions
                [entry_instruction as usize..(entry_instruction + num_instructions) as usize],
        );

        for basic_block in original_program.blocks.iter() {
            // Encode the decoded instructions
            let encoded_instructions: Vec<u32> = basic_block.encode();

            // Decode the encoded instructions
            let re_decoded_program = decode_until_end_of_a_block(&encoded_instructions);

            // Compare the original and re-decoded blocks
            assert_eq!(
                encoded_instructions.len(),
                re_decoded_program.len(),
                "Number of instructions mismatch"
            );

            // Check individual instruction inside the basic block
            for (original, re_decoded) in basic_block.0.iter().zip(re_decoded_program.0.iter()) {
                assert_eq!(
                    original, re_decoded,
                    "Instruction mismatch:\nOriginal: {}\nRe-decoded: {}",
                    original, re_decoded
                );
            }
        }
    }
}
