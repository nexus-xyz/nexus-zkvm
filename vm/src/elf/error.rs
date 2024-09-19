use thiserror::Error;

/// Errors related to VM initialization and execution
#[derive(Debug, Error)]
pub enum ParserError {
    /// Not a 32-bit ELF file
    #[error("not a 32-bit ELF file")]
    Not32Bit,

    /// Not a RISC-V ELF file
    #[error("not a RISC-V ELF file")]
    NotRiscV,

    /// Not a executable ELF file
    #[error("not an executable ELF file")]
    NotExecutable,

    /// Invalid virtual address when converting from 64-bit to 32-bit
    #[error("invalid virtual address")]
    InvalidVirtualAddress,

    /// Invalid file size when converting from 64-bit to 32-bit
    #[error("invalid file size")]
    InvalidFileSize,

    /// Invalid memory size when converting from 64-bit to 32-bit
    #[error("invalid memory size")]
    InvalidMemorySize,

    /// Virtual address is unaligned
    #[error("Unaligned virtual address")]
    UnalignedVirtualAddress,

    /// Segment size exceeeds maximum memory size
    #[error("Segment size exceeds maximum memory size")]
    SegmentSizeExceedsMemorySize,

    /// Invalid segment offset when converting from 64-bit to 32-bit
    #[error("invalid segment offset")]
    InvalidSegmentOffset,

    /// Invalid segment address
    #[error("invalid segment address")]
    InvalidSegmentAddress,

    /// Address exceeds memory size
    #[error("address exceeds memory size")]
    AddressExceedsMemorySize,

    /// No segment avaliable to load
    #[error("no segment avaliable to load")]
    NoSegmentAvailable,

    /// No program header
    #[error("no program header")]
    NoProgramHeader,

    /// No Section header
    #[error("no section header")]
    NoSectionHeader,

    /// No string table
    #[error("no string table")]
    NoStringTable,

    /// Duplicate memory address, our parser has problems
    #[error("duplicate memory address")]
    DuplicateMemoryAddress,

    /// Invalid entry point offset when converting from 64-bit to 32-bit
    #[error("invalid entry point offset")]
    InvalidEntryPointOffset,

    /// An error occurred while parsing the ELF headers
    #[error(transparent)]
    ELFError(#[from] elf::ParseError),
}

/// Result type for VM functions that can produce errors
pub type Result<T, E = ParserError> = std::result::Result<T, E>;
