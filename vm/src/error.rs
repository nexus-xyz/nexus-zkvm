use std::{backtrace::Backtrace, fmt::Display, num::TryFromIntError, panic::Location};

pub use nexus_common::error::*;

use nexus_common::riscv::Opcode;
use thiserror::Error;

use crate::elf::ElfError;

#[derive(Debug)]
pub struct VMError {
    pub source: VMErrorKind,
    pub location: &'static Location<'static>,
    pub backtrace: Backtrace,
}

impl Display for VMError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} at ", self.source)?;
        writeln!(f, "Location: {}", self.location)?;
        write!(f, "Backtrace: {}", self.backtrace)?;
        Ok(())
    }
}

impl core::error::Error for VMError {}

impl<T> From<T> for VMError
where
    T: Into<VMErrorKind>,
{
    fn from(source: T) -> Self {
        VMError {
            source: source.into(),
            location: Location::caller(),
            backtrace: Backtrace::capture(),
        }
    }
}

/// Errors related to VM operations.
#[derive(Debug, Error, PartialEq)]
pub enum VMErrorKind {
    // Unimplemented syscall
    #[error("Unimplemented syscall: opcode={0:08X}, pc=0x{1:08X}")]
    UnimplementedSyscall(u32, u32),

    // Non-syscall called as a syscall
    #[error("Instruction called as a syscall: opcode={0}, pc=0x{1:08X}")]
    InstructionNotSyscall(Opcode, u32),

    // Invalid memory layout
    #[error("Invalid memory layout")]
    InvalidMemoryLayout,

    // VM has run out of instructions to execute.
    #[error("VM has run out of instructions to execute")]
    VMOutOfInstructions,

    // VM has exited with status code.
    #[error("VM has exited with status code {0}")]
    VMExited(u32),

    // Invalid Profile Label.
    #[error("Invalid profile label for cycle counter: \"{0}\"")]
    InvalidProfileLabel(String),

    #[error("Wrapped MemoryError: {0}")]
    MemoryError(#[from] nexus_common::error::MemoryError),

    #[error("Wrapped OpcodeError: {0}")]
    OpcodeError(#[from] nexus_common::error::OpcodeError),

    #[error("Instruction not found in registry")]
    InstructionNotFound,

    // Duplicate Opcode and Instruction.
    #[error("Duplicate Opcode/Instruction in registry")]
    DuplicateInstruction(Opcode),

    // Undefined instruction
    #[error("Undefined instruction \"{0}\"")]
    UndefinedInstruction(Opcode),

    // Unimplemented instruction (with a valid opcode)
    #[error("Unimplemented instruction \"{0}\"")]
    UnimplementedInstruction(Opcode),

    // Unimplemented instruction (with a valid opcode) found at a specific PC
    #[error("Unimplemented instruction \"{0}\" at pc=0x{1:08X}")]
    UnimplementedInstructionAt(Opcode, u32),

    // Unsupported instruction (i.e., one with an invalid opcode)
    #[error("Unsupported instruction \"{0}\"")]
    UnsupportedInstruction(Opcode),

    #[error("Integer overflow")]
    IntOverflowError(#[from] TryFromIntError),

    // ElfError wrapper
    #[error("Wrapped ElfError: {0}")]
    ElfError(#[from] ElfError),

    // Merging non-contiguous memory segments
    #[error("Non-contiguous memory")]
    NonContiguousMemory,
}

/// Result type for VM functions that can produce errors.
pub type Result<T, E = VMError> = std::result::Result<T, E>;
