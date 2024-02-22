use thiserror::Error;

/// Errors related to VM initialization and execution
#[derive(Debug, Error)]
pub enum NexusVMError {
    /// Invalid instruction format, could not parse
    #[error("invalid instruction {1} at {0}")]
    InvalidInstruction(u64, u32),

    /// Unknown ECALL number
    #[error("unknown syscall {1} at {0}")]
    UnknownSyscall(u32, u32),

    /// Invalid memory address
    #[error("invalid memory access {0:x}")]
    SegFault(u32),

    /// Invalid memory alignment
    #[error("misaligned memory access {0:x}")]
    Misaligned(u32),

    /// An error occured while hashing
    #[error("error hashing {0}")]
    HashError(String),

    /// An error occurred reading file system
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// An error occurred while parsing the ELF headers
    #[error(transparent)]
    ELFError(#[from] elf::ParseError),

    /// ELF format not supported
    #[error("ELF format not supported: {0}")]
    ELFFormat(&'static str),

    /// RiscV parsing failed
    #[error(transparent)]
    RVError(#[from] nexus_riscv::VMError),
}

pub(crate) type Result<T, E = NexusVMError> = std::result::Result<T, E>;
