use thiserror::Error;

/// Errors related to VM initialization and execution
#[derive(Debug, Error)]
pub enum NexusVMError {
    /// not enough bytes available to complete instruction parse
    #[error("partial instruction at pc:{0:x}")]
    PartialInstruction(u32),

    /// Invalid instruction size found during parse
    #[error("invalid instruction size, {1}, at pc:{0:x}")]
    InvalidSize(u32, u32),

    /// Invalid instruction format, could not parse
    #[error("invalid instruction {1:x} at pc:{0:x}")]
    InvalidInstruction(u32, u32),

    /// Unknown ECALL number
    #[error("unknown ecall {1} at pc:{0:x}")]
    UnknownECall(u32, u32),

    /// An I/O error occurred
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Unknown (test) machine
    #[error("unknown machine {0}")]
    UnknownMachine(String),

    /// An error occurred while parsing the ELF headers
    #[error(transparent)]
    ELFError(#[from] elf::ParseError),

    /// ELF format not supported
    #[error("ELF format not supported: {0}")]
    ELFFormat(&'static str),

    /// Invalid memory alignment
    #[error("misaligned memory access {0:x}")]
    Misaligned(u32),

    /// An error occured while hashing
    #[error("error hashing {0}")]
    HashError(String),

    /// Reached the limit of executed instructions.
    #[error("reached maximum number of executed instructions: {0}")]
    MaxTraceLengthExceeded(usize),

    /// Benchmark labels are invalid.
    #[error("Labels are invalid.")]
    InvalidProfileLabel,
}

/// Result type for VM functions that can produce errors
pub type Result<T, E = NexusVMError> = std::result::Result<T, E>;
