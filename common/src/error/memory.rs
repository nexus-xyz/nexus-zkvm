use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum MemoryError {
    // Cannot write unaligned memory
    #[error("Unaligned memory write: 0x{0:08X}")]
    UnalignedMemoryWrite(u32),

    // Cannot read unaligned memory
    #[error("Unaligned memory read: 0x{0:08X}")]
    UnalignedMemoryRead(u32),

    // Invalid memory access
    #[error("Invalid memory access at 0x{0:08X}: {1}")]
    InvalidMemoryAccess(u32, &'static str),

    // Address calculation overflow
    #[error("Address calculation overflow")]
    AddressCalculationOverflow,

    // Address calculation underflow
    #[error("Address calculation underflow")]
    AddressCalculationUnderflow,

    // Address overflow during memory operation
    #[error("Address overflow during memory operation")]
    AddressOverflow,

    // Attempted to read a write-only memory address
    #[error(
        "Unauthorized read access: Attempted to read from write-only memory at address 0x{0:08X}"
    )]
    UnauthorizedRead(u32),

    // Attempted to write a read-only memory address
    #[error(
        "Unauthorized write access: Attempted to write to read-only memory at address 0x{0:08X}"
    )]
    UnauthorizedWrite(u32),

    // Tried to access an unknown memory
    #[error("Memory access error: Attempted to access undefined memory region")]
    UndefinedMemoryRegion,

    // Multiple memories report owning the same address
    #[error(
        "Memory overlap detected: Multiple memory regions claim ownership of the same address"
    )]
    MemoryOverlap,

    // Invalid memory segment
    #[error("Invalid memory segment")]
    InvalidMemorySegment,
}
