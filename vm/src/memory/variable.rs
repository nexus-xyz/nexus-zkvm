//! Variable Memory Implementation
//!
//! This module provides a variable-size memory implementation with different access modes.
//! It supports Read-Only (RO), Write-Only (WO), and Read-Write (RW) memory types.
//!
//! # Key Components
//!
//! - `VariableMemory<M>`: A generic struct representing variable-size memory with a specific access mode.
//! - `MemoryProcessor`: A trait implemented by `VariableMemory` for different access modes.
//!
//! # Features
//!
//! - Dynamic memory allocation: Only allocates memory for addresses that have been written to.
//! - Supports byte, halfword, and word-sized read and write operations.
//! - Implements alignment checks for memory operations.
//! - Provides methods for creating memory from a `BTreeMap`.
//! - Includes debug formatting for easy visualization of memory contents.
//! - Supports reading contiguous memory segments.
//!
//! # Usage
//!
//! ```rust
//! use nexus_vm::memory::{VariableMemory, MemoryProcessor, MemAccessSize, RW};
//!
//! // Create a new RW variable memory
//! let mut memory = VariableMemory::<RW>::default();
//!
//! // Write a word to memory
//! memory.write(0x1000, MemAccessSize::Word, 0xABCD1234).unwrap();
//!
//! // Read a byte from memory
//! let value = memory.read(0x1000, MemAccessSize::Byte).unwrap();
//!
//! ```
//!
//! # Error Handling
//!
//! The module uses `Result` types with `MemoryError` for error handling, covering cases such as:
//! - Unaligned memory access
//! - Unauthorized read/write operations
//! - Invalid memory segments
//!
//! # Testing
//!
//! Comprehensive unit tests are included to verify the correctness of memory operations
//! across different access modes and sizes, as well as the functionality of memory segments.
//!
//! # Performance Considerations
//!
//! We expect memory to be densely populated, so we use a contiguous vector to store the data.
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomData;

use nexus_common::constants::WORD_SIZE;
use nexus_common::error::MemoryError;

use super::{
    LoadOp, MemAccessSize, MemoryProcessor, MemorySegmentImage, Mode, PagedMemory, StoreOp, RO, RW,
    WO,
};

#[derive(Default, Clone)]
pub struct VariableMemory<M: Mode> {
    store: PagedMemory,
    _phantom_data: PhantomData<M>,
}

impl<M: Mode> From<MemorySegmentImage> for VariableMemory<M> {
    fn from(image: MemorySegmentImage) -> Self {
        let mut memory = PagedMemory::new();

        // Safety: this is a more general/less constrained type of memory than `MemorySegmentImage`.
        memory
            .set_words(image.base(), image.as_word_slice())
            .unwrap();

        VariableMemory::<M> {
            store: memory,
            _phantom_data: PhantomData,
        }
    }
}

impl<M: Mode> Debug for VariableMemory<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "┌─────────────────────────────────────┐")?;
        writeln!(f, "│         Variable Memory             │")?;
        writeln!(f, "├───────────────────┬─────────────────┤")?;
        writeln!(f, "│     Address       │      Value      │")?;
        writeln!(f, "├───────────────────┼─────────────────┤")?;

        for (address, value) in self.addressed_iter() {
            writeln!(f, "│ 0x{:08x}        │ 0x{:08x}      │", address, value)?;
        }

        writeln!(f, "└───────────────────┴─────────────────┘")?;
        Ok(())
    }
}

impl<M: Mode> VariableMemory<M> {
    /// Writes data to memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address to write to.
    /// * `size` - The size of the write operation.
    /// * `value` - The value to write.
    ///
    /// # Returns
    ///
    /// The value written to memory, or an error if the operation failed.
    fn execute_write(
        &mut self,
        address: u32,
        size: MemAccessSize,
        value: u32,
    ) -> Result<StoreOp, MemoryError> {
        let (shift, mask) = size.get_shift_and_mask(address);

        // Check for alignment
        if !size.is_aligned(address) {
            return Err(MemoryError::UnalignedMemoryWrite(address));
        }

        // Align to word boundary
        let aligned_address = address & !(WORD_SIZE - 1) as u32;
        let write_mask = !(mask << shift);
        let data = (value & mask) << shift;

        let prev_word = self.get_word(aligned_address)?.unwrap_or(0);

        self.insert_word(aligned_address, (prev_word & write_mask) | data)?;

        Ok(StoreOp::Op(
            size,
            address,
            value,                       // new value
            (prev_word >> shift) & mask, // old value
        ))
    }

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
    fn execute_read(&self, address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        let (shift, mask) = size.get_shift_and_mask(address);

        if !size.is_aligned(address) {
            return Err(MemoryError::UnalignedMemoryRead(address));
        }

        // Align to word boundary
        let aligned_address = address & !(WORD_SIZE - 1) as u32;

        let value = self
            .get_word(aligned_address)?
            .map(|value| ((value >> shift) & mask))
            .unwrap_or(0);

        Ok(LoadOp::Op(size, address, value))
    }
    /// For bounded segments, returns a slice of memory between start and end addresses if they form a contiguous segment.
    ///
    /// For unbounded segments, returns the longest contiguous segment starting from the start address.
    /// If the segment is empty, then an empty Vec is returned.
    ///
    /// In both cases, start and end should be word-aligned (if set).
    ///
    /// Returns an error if the segment is not contiguous.
    pub fn segment_words(
        &self,
        start: u32,
        end: Option<u32>,
    ) -> Result<impl Iterator<Item = u32> + '_, MemoryError> {
        self.store.range_words_iter(start, end)
    }

    pub fn segment_bytes(&self, start: u32, end: Option<u32>) -> Result<Vec<u8>, MemoryError> {
        self.store.range_bytes(start, end)
    }

    /// Returns the length of the segment in bytes that are actually set.
    pub fn occupied_bytes(&self) -> u32 {
        self.store.occupied_bytes()
    }

    /// Returns the length of the segment in bytes that are actually set.
    pub fn bytes_spanned(&self) -> u32 {
        self.store.bytes_spanned()
    }

    /// Returns a word-addressed iterator over the memory, yielding (address, value) pairs.
    pub fn addressed_iter(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.store.addressed_iter()
    }

    pub fn get_word(&self, address: u32) -> Result<Option<u32>, MemoryError> {
        self.store.get_word(address)
    }

    pub fn insert_word(&mut self, address: u32, value: u32) -> Result<Option<u32>, MemoryError> {
        self.store.set_word(address, value)
    }
}

impl MemoryProcessor for VariableMemory<RW> {
    /// Writes data to memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address to write to.
    /// * `size` - The size of the write operation.
    /// * `value` - The value to write.
    ///
    /// # Returns
    ///
    /// The value written to memory, or an error if the operation failed.
    fn write(
        &mut self,
        raw_address: u32,
        size: MemAccessSize,
        value: u32,
    ) -> Result<StoreOp, MemoryError> {
        VariableMemory::execute_write(self, raw_address, size, value)
    }

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
    fn read(&self, raw_address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        VariableMemory::execute_read(self, raw_address, size)
    }
}

impl MemoryProcessor for VariableMemory<RO> {
    /// Writes data to memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address to write to.
    /// * `size` - The size of the write operation.
    /// * `value` - The value to write.
    ///
    /// # Returns
    ///
    /// The value written to memory, or an error if the operation failed.
    fn write(
        &mut self,
        raw_address: u32,
        _size: MemAccessSize,
        _value: u32,
    ) -> Result<StoreOp, MemoryError> {
        Err(MemoryError::UnauthorizedWrite(raw_address))
    }

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
    fn read(&self, raw_address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        VariableMemory::execute_read(self, raw_address, size)
    }
}

impl MemoryProcessor for VariableMemory<WO> {
    /// Writes data to memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address to write to.
    /// * `size` - The size of the write operation.
    /// * `value` - The value to write.
    ///
    /// # Returns
    ///
    /// The value written to memory, or an error if the operation failed.
    fn write(
        &mut self,
        raw_address: u32,
        size: MemAccessSize,
        value: u32,
    ) -> Result<StoreOp, MemoryError> {
        VariableMemory::execute_write(self, raw_address, size, value)
    }

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
    fn read(&self, raw_address: u32, _size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        Err(MemoryError::UnauthorizedRead(raw_address))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn test_write_and_read_byte() {
        let mut memory = VariableMemory::<RW>::default();

        // Write bytes at different alignments
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Byte, 0xAB),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x1000, 0xAB, 0x00))
        );
        assert_eq!(
            memory.write(0x1001, MemAccessSize::Byte, 0xCD),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x1001, 0xCD, 0x00))
        );
        assert_eq!(
            memory.write(0x1002, MemAccessSize::Byte, 0xEF),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x1002, 0xEF, 0x00))
        );
        assert_eq!(
            memory.write(0x1003, MemAccessSize::Byte, 0x12),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x1003, 0x12, 0x00))
        );

        // Read bytes
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1000, 0xAB))
        );
        assert_eq!(
            memory.read(0x1001, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1001, 0xCD))
        );
        assert_eq!(
            memory.read(0x1002, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1002, 0xEF))
        );
        assert_eq!(
            memory.read(0x1003, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1003, 0x12))
        );

        // Read the whole word
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x1000, 0x12EFCDAB))
        );
    }

    #[test]
    fn test_write_and_read_halfword() {
        let mut memory = VariableMemory::<RW>::default();

        // Write halfwords at aligned addresses
        assert_eq!(
            memory.write(0x1000, MemAccessSize::HalfWord, 0xABCD),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x1000, 0xABCD, 0x0000)),
        );
        assert_eq!(
            memory.write(0x1002, MemAccessSize::HalfWord, 0xEF12),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x1002, 0xEF12, 0x0000)),
        );

        // Read halfwords
        assert_eq!(
            memory.read(0x1000, MemAccessSize::HalfWord),
            Ok(LoadOp::Op(MemAccessSize::HalfWord, 0x1000, 0xABCD))
        );
        assert_eq!(
            memory.read(0x1002, MemAccessSize::HalfWord),
            Ok(LoadOp::Op(MemAccessSize::HalfWord, 0x1002, 0xEF12))
        );

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x1001, MemAccessSize::HalfWord, 0x3456),
            Err(MemoryError::UnalignedMemoryWrite(0x1001))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x1001, MemAccessSize::HalfWord),
            Err(MemoryError::UnalignedMemoryRead(0x1001))
        );
    }

    #[test]
    fn test_write_and_read_word() {
        let mut memory = VariableMemory::<RW>::default();

        // Write a word at an aligned address
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Ok(StoreOp::Op(
                MemAccessSize::Word,
                0x1000,
                0xABCD1234,
                0x00000000
            )),
        );

        // Read the word
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x1000, 0xABCD1234))
        );

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x1001, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x1001))
        );
        assert_eq!(
            memory.write(0x1002, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x1002))
        );
        assert_eq!(
            memory.write(0x1003, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x1003))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x1001, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x1001))
        );
        assert_eq!(
            memory.read(0x1002, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x1002))
        );
        assert_eq!(
            memory.read(0x1003, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x1003))
        );
    }

    #[test]
    fn test_overwrite() {
        let mut memory = VariableMemory::<RW>::default();

        // Write a word
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Ok(StoreOp::Op(
                MemAccessSize::Word,
                0x1000,
                0xABCD1234,
                0x00000000
            )),
        );

        // Overwrite with bytes
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Byte, 0xEF),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x1000, 0xEF, 0x34))
        );
        assert_eq!(
            memory.write(0x1001, MemAccessSize::Byte, 0x56),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x1001, 0x56, 0x12))
        );
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x1000, 0xABCD56EF))
        );

        // Overwrite with a halfword
        assert_eq!(
            memory.write(0x1002, MemAccessSize::HalfWord, 0x7890),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x1002, 0x7890, 0xABCD)),
        );
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x1000, 0x789056EF))
        );
    }

    #[test]
    fn test_uninitialized_read() {
        let memory = VariableMemory::<RW>::default();

        // Read from an uninitialized address
        assert_eq!(
            memory.read(0x2000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x2000, 0x00000000))
        );
    }

    #[test]
    fn test_function_read_write_bytes() {
        let mut memory = VariableMemory::<RW>::default();

        // Test write_bytes
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        assert!(memory.write_bytes(0x1000, &data).is_ok());

        // Test read_bytes
        let result = memory.read_bytes(0x1000, 5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);

        // Test reading more bytes than written
        let result = memory.read_bytes(0x1000, 8);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00]
        );

        // Test writing and reading across word boundaries
        let data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert!(memory.write_bytes(0x1002, &data).is_ok());

        let result = memory.read_bytes(0x1000, 10);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            vec![0xAA, 0xBB, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );

        // Test reading individual bytes after write_bytes
        assert_eq!(
            memory.read(0x1002, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1002, 0x11))
        );
        assert_eq!(
            memory.read(0x1003, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1003, 0x22))
        );
        assert_eq!(
            memory.read(0x1004, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1004, 0x33))
        );
        assert_eq!(
            memory.read(0x1005, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x1005, 0x44))
        );

        // Test reading words after write_bytes
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x1000, 0x2211BBAA))
        );
        assert_eq!(
            memory.read(0x1004, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x1004, 0x66554433))
        );
    }

    #[test]
    fn test_unpermitted_read() {
        let mut map: BTreeMap<u32, u32> = BTreeMap::new();
        map.insert(0x1000, 0xABCD1234);
        let memory_image = MemorySegmentImage::try_from_contiguous_btree(&map).unwrap();

        let memory = VariableMemory::<WO>::from(memory_image);

        // Read from an address in a write-only memory
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Err(MemoryError::UnauthorizedRead(0x1000))
        );
    }

    #[test]
    fn test_unpermitted_write() {
        let mut memory = VariableMemory::<RO>::default();

        // Write to an address in a read-only memory
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::UnauthorizedWrite(0x1000))
        );
    }
}
