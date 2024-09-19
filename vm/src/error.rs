use thiserror::Error;

use crate::riscv::Opcode;

/// Errors related to VM operations
#[derive(Debug, Error, PartialEq)]
pub enum VMError {
    // Cannot write unalgined memory
    #[error("Unaligned memory write")]
    UnalignedMemoryWrite(u32),

    // Cannot read unalgined memory
    #[error("Unaligned memory read")]
    UnalignedMemoryRead(u32),

    // Invalid memory access
    #[error("Invalid memory access: 0x{0:08X}")]
    InvalidMemoryAccess(u32),

    // Address calcuation overflow
    #[error("Address calculation overflow")]
    AddressCalculationOverflow,

    // Unsupport instruction
    #[error("Unsupported instruction")]
    UnsupportedInstruction(u32),

    // Unimplemented instruction
    #[error("Unimplemented instruction")]
    UnimplementedInstruction(u32),

    // VM has stoped
    #[error("VM has stopped")]
    VMStopped,

    // Duplicate Opcode and Instruction
    #[error("Duplicate Opcode/Instruction")]
    DuplicateInstruction(Opcode),

    // Unable to lock instruction executor
    #[error("Unable to lock instruction executor")]
    InstructionExecutorLockError(String),
}

/// Result type for VM functions that can produce errors
pub type Result<T, E = VMError> = std::result::Result<T, E>;
