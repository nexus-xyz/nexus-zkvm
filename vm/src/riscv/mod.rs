mod decoder;
mod instructions;

pub use decoder::{decode_instructions, decode_until_end_of_a_block};
pub use instructions::{
    BasicBlock, BasicBlockProgram, Instruction, InstructionType, Opcode, Register,
};
