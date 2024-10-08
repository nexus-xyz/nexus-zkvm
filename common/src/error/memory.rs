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
    #[error("Invalid memory access: 0x{0:08X}")]
    InvalidMemoryAccess(u32),

    // Address calculation overflow
    #[error("Address calculation overflow")]
    AddressCalculationOverflow,
}
