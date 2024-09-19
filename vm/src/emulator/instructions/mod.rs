mod alu_instructions;
mod branch_instructions;
mod instruction_executor;
mod macros;
mod memory_instructions;
mod system_instructions;

pub use instruction_executor::{InstructionExecutorFn, INSTRUCTION_EXECUTOR};
