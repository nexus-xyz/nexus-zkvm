use crate::error::Result;

#[derive(Debug, Clone, Copy)]
/// Represents the size of memory access operations.
/// The value of enum is for efficient masking purpose.
pub enum MemAccessSize {
    Byte = 0,
    HalfWord = 1,
    Word = 3,
}

// Helper function to get shift and mask for different access sizes
pub(crate) fn get_shift_and_mask(size: MemAccessSize, address: u32) -> (u32, u32) {
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
    fn read(&self, address: u32, size: MemAccessSize) -> Result<u32>;

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
    fn write(&mut self, address: u32, size: MemAccessSize, value: u32) -> Result<u32>;
}
