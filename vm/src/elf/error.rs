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
    InvalidVirtualAddress(u64),

    /// Invalid file size when converting from 64-bit to 32-bit
    #[error("invalid file size")]
    InvalidFileSize,

    /// Invalid memory size when converting from 64-bit to 32-bit
    #[error("invalid memory size")]
    InvalidMemorySize,

    /// Invalid section index
    #[error("invalid section index {0:x}")]
    InvalidSectionIndex(u16),

    /// Virtual address is unaligned
    #[error("Unaligned virtual address")]
    UnalignedVirtualAddress,

    /// Segment size exceeds maximum memory size
    #[error("Segment size exceeds maximum memory size")]
    SegmentSizeExceedsMemorySize,

    /// Invalid section address when converting from 64-bit to 32-bit
    #[error("invalid section address")]
    InvalidSectionAddress(u64),

    /// Invalid section offset when converting from 64-bit to 32-bit
    #[error("invalid section offset")]
    InvalidSectionOffset(u64),

    /// Invalid segment offset when converting from 64-bit to 32-bit
    #[error("invalid segment offset")]
    InvalidSegmentOffset,

    /// Invalid segment address
    #[error("invalid segment address")]
    InvalidSegmentAddress,

    /// Address exceeds memory size
    #[error("address exceeds memory size")]
    AddressExceedsMemorySize,

    /// No segment available to load
    #[error("no segment available to load")]
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

    /// The symbol table doesn't exist.
    #[error("no symbol table")]
    NoSymbolTable,

    /// Duplicate memory address, our parser has problems
    #[error("duplicate memory address")]
    DuplicateMemoryAddress,

    /// Invalid entry point offset when converting from 64-bit to 32-bit
    #[error("invalid entry point offset")]
    InvalidEntryPointOffset,

    /// An error occurred while parsing the ELF headers
    #[error(transparent)]
    ELFError(#[from] elf::ParseError),

    /// An error occurred while decoding a byte slice into a word.
    #[error(transparent)]
    WordDecodingFailed(#[from] std::array::TryFromSliceError),

    /// An error occurred while parsing an integer from a string.
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    /// File contained more than MAX_PRECOMPILES precompiles.
    #[error("ELF file contains too many precompiles ({0})")]
    TooManyPrecompiles(u16),

    /// File had more than one precompile description for some precompile.
    #[error("ELF file contains duplicate precompile ({0})")]
    DuplicatePrecompile(u16),

    /// File is missing a precompile (some later number precompile exists but this one does not).
    #[error("ELF file is missing precompile ({0})")]
    MissingPrecompile(u16),

    /// Some string couldn't be correctly decoded.
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    /// An issue occurred interacting with the filesystem.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// The precompile size is invalid.
    #[error("Invalid precompile size: {0}")]
    InvalidPrecompileSize(u64),

    /// The calculated offset of the symbol is before the start of the section that houses it.
    #[error("Invalid offset in section")]
    InvalidOffsetInSection,

    /// The calculated offset is not within the file.
    #[error("Invalid offset in file")]
    InvalidOffsetInFile,

    // Btree memory segment has unexpected gaps
    #[error("Memory segment has unexpected gaps")]
    GappyMemorySegment,

    // Btree memory segment has unexpected overlaps
    #[error("Memory segment has unexpected overlaps")]
    OverlappingMemorySegment,

    // Could not find a .text section in the ELF file
    #[error("No executable segment found")]
    NoExecutableSegment,
}

impl PartialEq for ParserError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ELFError(a), Self::ELFError(b)) => a.to_string() == b.to_string(),
            // This type has no data, so any instance of this error is the same as another.
            (Self::WordDecodingFailed(_), Self::WordDecodingFailed(_)) => true,
            (Self::IOError(a), Self::IOError(b)) => a.to_string() == b.to_string(),
            (a, b) => a == b,
        }
    }
}
