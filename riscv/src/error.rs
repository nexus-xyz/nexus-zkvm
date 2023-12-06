use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

/// Errors related to VM initialization and execution
#[derive(Debug)]
pub enum VMError {
    /// not enough bytes available to complete instruction parse
    PartialInstruction(u32),

    /// Invalid instruction size found during parse
    InvalidSize(u32, u32),

    /// Invalid instruction format, could not parse
    InvalidInstruction(u32, u32),

    /// Unknown ECALL number
    UnknownECall(u32, u32),

    /// Invalid memory address
    SegFault(u32),

    /// Invalid memory alignment
    Misaligned(u32),

    /// An error occurred reading file system
    IOError(std::io::Error),

    /// An error occurred while parsing the ELF headers
    ELFError(elf::ParseError),
}
use VMError::*;

/// Result type for VM functions that can produce errors
pub type Result<T> = std::result::Result<T, VMError>;

impl From<std::io::Error> for VMError {
    fn from(x: std::io::Error) -> VMError {
        IOError(x)
    }
}

impl From<elf::ParseError> for VMError {
    fn from(x: elf::ParseError) -> VMError {
        ELFError(x)
    }
}

impl Error for VMError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IOError(e) => Some(e),
            ELFError(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for VMError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PartialInstruction(pc) => write!(f, "partial instruction at pc:{pc:x}"),
            InvalidSize(pc, sz) => write!(f, "invalid instruction size, {sz}, at pc:{pc:x}"),
            InvalidInstruction(pc, i) => write!(f, "invalid instruction {i:x} at pc:{pc:x}"),
            UnknownECall(pc, n) => write!(f, "unknown ecall {n} at pc:{pc:x}"),
            SegFault(addr) => write!(f, "invalid memory address {addr:x}"),
            Misaligned(addr) => write!(f, "mis-alligned memory address {addr:x}"),
            IOError(e) => write!(f, "{e}"),
            ELFError(e) => write!(f, "{e}"),
        }
    }
}
