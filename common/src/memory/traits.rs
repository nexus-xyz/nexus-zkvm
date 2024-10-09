use crate::error::MemoryError;

/// A trait for permissions modes for memories.
pub trait Mode {}

/// A read-write indicator type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum RW {
    #[default]
    ReadWrite,
}
impl Mode for RW {}

/// A read-only indicator type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum RO {
    #[default]
    ReadOnly,
}
impl Mode for RO {}

/// A write-only indicator type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum WO {
    #[default]
    WriteOnly,
}
impl Mode for WO {}

/// A no-access indicator type. Useful for associated data and padding.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum NA {
    #[default]
    NoAccess,
}
impl Mode for NA {}

#[derive(Debug, Clone, Copy)]
/// Represents the size of memory access operations.
/// The value of enum is for efficient masking purpose.
pub enum MemAccessSize {
    Byte = 0,
    HalfWord = 1,
    Word = 3,
}

// Helper function to get shift and mask for different access sizes
pub fn get_shift_and_mask(size: MemAccessSize, address: u32) -> (u32, u32) {
    match size {
        MemAccessSize::Byte => ((address & 0x3) * 8, 0xff),
        MemAccessSize::HalfWord => ((address & 0x2) * 8, 0xffff),
        MemAccessSize::Word => (0, 0xffffffff),
    }
}

/// A trait for processing memory operations.
///
/// This trait defines the interface for reading from and writing to memory.
/// Implementors of this trait should handle memory access operations based on
/// their specific requirements and memory model.
pub trait MemoryProcessor: Default {
    /// Reads a value from memory at the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address to read from.
    /// * `size` - The size of the memory access operation.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the read value or an error.
    fn read(&self, address: u32, size: MemAccessSize) -> Result<u32, MemoryError>;

    /// Writes a value to memory at the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address to write to.
    /// * `size` - The size of the memory access operation.
    /// * `value` - The value to write to memory.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the write operation.
    fn write(&mut self, address: u32, size: MemAccessSize, value: u32) -> Result<u32, MemoryError>;

    /// Reads multiple bytes from memory at the specified address, built on top of `read`.
    fn read_bytes(&self, address: u32, size: usize) -> Result<Vec<u8>, MemoryError> {
        let mut data = vec![0; size];
        for (i, byte) in data.iter_mut().enumerate().take(size) {
            *byte = self.read(address + i as u32, MemAccessSize::Byte)? as u8;
        }
        Ok(data)
    }

    /// Writes multiple bytes to memory at the specified address, built on top of `write`.
    fn write_bytes(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryError> {
        for (i, &byte) in data.iter().enumerate() {
            self.write(address + i as u32, MemAccessSize::Byte, byte as u32)?;
        }
        Ok(())
    }
}
