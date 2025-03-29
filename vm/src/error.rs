pub use nexus_common::error::*;

use nexus_common::riscv::Opcode;
use thiserror::Error;

/// Errors related to VM operations.
#[derive(Debug, Error, PartialEq)]
pub enum VMError {
    // Unimplemented syscall
    #[error("Unimplemented syscall: opcode={0:08X}, pc=0x{1:08X}")]
    UnimplementedSyscall(u32, u32),

    // Non-syscall called as a syscall
    #[error("Instruction called as a syscall: opcode={0}, pc=0x{1:08X}")]
    InstructionNotSyscall(Opcode, u32),

    // Invalid memory layout
    #[error("Invalid memory layout: Memory regions are incorrectly configured or overlapping")]
    InvalidMemoryLayout,

    // VM has run out of instructions to execute.
    #[error("VM has run out of instructions to execute: Maximum instruction limit reached")]
    VMOutOfInstructions,

    // VM has exited with status code.
    #[error("VM has exited with status code {0}")]
    VMExited(u32),

    // Invalid Profile Label.
    #[error("Invalid profile label for cycle counter: \"{0}\" is not a recognized profile name")]
    InvalidProfileLabel(String),

    #[error("Wrapped MemoryError: {0}")]
    MemoryError(#[from] nexus_common::error::MemoryError),

    #[error("Wrapped OpcodeError: {0}")]
    OpcodeError(#[from] nexus_common::error::OpcodeError),

    #[error("Instruction not found in registry: The instruction was not registered in the instruction set")]
    InstructionNotFound,

    // Duplicate Opcode and Instruction.
    #[error("Duplicate Opcode/Instruction in registry: An instruction with the same opcode is already registered")]
    DuplicateInstruction(Opcode),

    // Undefined instruction
    #[error("Undefined instruction \"{0}\"")]
    UndefinedInstruction(Opcode),

    // Unimplemented instruction (with a valid opcode)
    #[error("Unimplemented instruction \"{0}\": The instruction is recognized but not implemented")]
    UnimplementedInstruction(Opcode),

    // Unimplemented instruction (with a valid opcode) found at a specific PC
    #[error("Unimplemented instruction \"{0}\" at pc=0x{1:08X}")]
    UnimplementedInstructionAt(Opcode, u32),

    // Unsupported instruction (i.e., one with an invalid opcode)
    #[error("Unsupported instruction \"{0}\": The instruction is not supported by this VM")]
    UnsupportedInstruction(Opcode),
}

/// Result type for VM functions that can produce errors.
pub type Result<T, E = VMError> = std::result::Result<T, E>;
