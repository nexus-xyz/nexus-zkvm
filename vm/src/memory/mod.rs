mod mem;

pub use mem::{MemAccessSize, Memory};

/// A trait for processing memory operations.
///
/// This trait defines the interface for reading from and writing to memory.
/// Implementors of this trait should handle memory access operations based on
/// their specific requirements and memory model.
pub trait MemoryProcessor: Default {
    /// The result type returned by read and write operations.
    type Result;

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
    fn read(&self, address: u32, size: MemAccessSize) -> Self::Result;

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
    fn write(&mut self, address: u32, size: MemAccessSize, value: u32) -> Self::Result;
}
