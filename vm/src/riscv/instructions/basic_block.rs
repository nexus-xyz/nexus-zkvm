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
        self.blocks.iter().map(|block| block.0.len()).sum()
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
