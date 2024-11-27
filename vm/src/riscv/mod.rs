pub(crate) mod decoder;
pub(crate) mod instructions;

pub use decoder::{decode_instruction, decode_instructions, decode_until_end_of_a_block};
pub use instructions::{
    BasicBlock, BasicBlockProgram, BuiltinOpcode, Instruction, InstructionType, Opcode,
};
pub use nexus_common::riscv::register::Register;
