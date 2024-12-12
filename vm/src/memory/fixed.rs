use std::{fmt::Debug, marker::PhantomData};

use nexus_common::constants::WORD_SIZE;
use nexus_common::error::MemoryError;
use nexus_common::{bytes_to_words, word_align, words_to_bytes};

use super::{LoadOp, MemAccessSize, MemoryProcessor, Mode, StoreOp, NA, RO, RW, WO};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct FixedMemory<M: Mode> {
    pub base_address: u32,
    pub max_len: usize,
    vec: Vec<u32>,
    __mode: PhantomData<M>,
}

macro_rules! impl_debug_for_fixed_memory {
    ($mode:ty, $mode_str:expr) => {
        impl Debug for FixedMemory<$mode> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                writeln!(f, "┌─────────────────────────────────────┐")?;
                writeln!(f, "│           {} Memory                 │", $mode_str)?;
                writeln!(f, "├───────────────────┬─────────────────┤")?;
                writeln!(f, "│     Address       │      Value      │")?;
                writeln!(f, "├───────────────────┼─────────────────┤")?;
                for (i, word) in self.vec.iter().enumerate() {
                    writeln!(
                        f,
                        "│ 0x{:08x}        │ 0x{:08x}      │",
                        self.base_address + i as u32 * WORD_SIZE as u32,
                        word
                    )?;
                }
                writeln!(f, "└───────────────────┴─────────────────┘")?;
                Ok(())
            }
        }
    };
}

// Use the macro for each memory type
impl_debug_for_fixed_memory!(RO, "RO ");
impl_debug_for_fixed_memory!(WO, "WO ");
impl_debug_for_fixed_memory!(RW, "RW ");
impl_debug_for_fixed_memory!(NA, "NA ");

impl<M: Mode> FixedMemory<M> {
    pub fn new(base_address: u32, max_len: usize) -> Self {
        FixedMemory::<M> {
            base_address,
            max_len,
            vec: Vec::<u32>::new(),
            __mode: PhantomData,
        }
    }

    pub fn from_vec(base_address: u32, max_len: usize, vec: Vec<u32>) -> Self {
        vec.to_owned().truncate(max_len / WORD_SIZE);

        FixedMemory::<M> {
            base_address,
            max_len,
            vec,
            __mode: PhantomData,
        }
    }

    pub fn from_bytes(base_address: u32, bytes: &[u8]) -> Self {
        let padded_len = word_align!(bytes.len());
        let mut padded_bytes = bytes.to_vec();
        padded_bytes.resize(padded_len, 0);
        FixedMemory::<M> {
            base_address,
            max_len: padded_len,
            vec: bytes_to_words!(padded_bytes),
            __mode: PhantomData,
        }
    }

    pub fn from_words(base_address: u32, max_len: usize, words: &[u32]) -> Self {
        let mut vec = words.to_vec();
        vec.truncate(max_len / WORD_SIZE);

        FixedMemory::<M> {
            base_address,
            max_len,
            vec,
            __mode: PhantomData,
        }
    }

    pub fn segment(&self, start: u32, end: Option<u32>) -> &[u32] {
        let s = (start - self.base_address) / WORD_SIZE as u32;

        if let Some(mut e) = end {
            e = (e - self.base_address) / WORD_SIZE as u32;
            &self.vec[s as usize..e as usize]
        } else {
            &self.vec[s as usize..]
        }
    }

    pub fn segment_bytes(&self, start: u32, end: Option<u32>) -> Vec<u8> {
        words_to_bytes!(self.segment(start, end))
    }
}

impl<M: Mode> FixedMemory<M> {
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
        raw_address: u32,
        size: MemAccessSize,
        value: u32,
    ) -> Result<StoreOp, MemoryError> {
        // Error if address is outside reserved space
        if raw_address < self.base_address {
            return Err(MemoryError::InvalidMemoryAccess(raw_address));
        }

        let address = raw_address - self.base_address;

        // Error if address is outside reserved space
        if address >= self.max_len as u32 {
            return Err(MemoryError::InvalidMemoryAccess(raw_address));
        }

        // Check for alignment
        if !size.is_aligned(address) {
            return Err(MemoryError::UnalignedMemoryWrite(raw_address));
        }

        // Align to word boundary
        let aligned_address = (address & !(WORD_SIZE - 1) as u32) as usize;
        let (shift, mask) = size.get_shift_and_mask(address);
        let word_index = aligned_address / WORD_SIZE;

        let write_mask = !(mask << shift);
        let data = (value & mask) << shift;

        let prev_value = if self.vec.len() <= word_index {
            // Resize the vector to the next word-aligned size
            self.vec.resize(word_index + 1, 0);

            0
        } else {
            (self.vec[word_index] >> shift) & mask
        };

        // Perform the write operation
        self.vec[word_index] &= write_mask;
        self.vec[word_index] |= data;

        Ok(StoreOp::Op(
            size,
            raw_address,
            (data >> shift) & mask,
            prev_value,
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
    fn execute_read(&self, raw_address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        // Error if address is outside reserved space
        if raw_address < self.base_address {
            return Err(MemoryError::InvalidMemoryAccess(raw_address));
        }

        let address = raw_address - self.base_address;

        // Error if address is outside reserved space
        if address >= self.max_len as u32 {
            return Err(MemoryError::InvalidMemoryAccess(raw_address));
        }

        // Check for alignment
        if !size.is_aligned(address) {
            return Err(MemoryError::UnalignedMemoryRead(raw_address));
        }

        // Align to word boundary
        let aligned_address = (address & !(WORD_SIZE - 1) as u32) as usize;
        let (shift, mask) = size.get_shift_and_mask(address);
        let word_index = aligned_address / WORD_SIZE;

        if self.vec.len() <= word_index {
            return Ok(LoadOp::Op(size, raw_address, u32::default()));
        }

        Ok(LoadOp::Op(
            size,
            raw_address,
            (self.vec[word_index] >> shift) & mask,
        ))
    }
}

impl MemoryProcessor for FixedMemory<RW> {
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
        FixedMemory::execute_write(self, raw_address, size, value)
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
        FixedMemory::execute_read(self, raw_address, size)
    }
}

impl MemoryProcessor for FixedMemory<RO> {
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
        FixedMemory::execute_read(self, raw_address, size)
    }
}

impl MemoryProcessor for FixedMemory<WO> {
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
        FixedMemory::execute_write(self, raw_address, size, value)
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

impl MemoryProcessor for FixedMemory<NA> {
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
    fn read(&self, raw_address: u32, _size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        Err(MemoryError::UnauthorizedRead(raw_address))
    }
}

#[cfg(test)]
mod tests {
    use nexus_common::error::MemoryError;

    use super::*;

    #[test]
    fn test_write_and_read_byte() {
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x16);

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
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x16);

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
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x16);

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
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x16);

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
    fn test_invalid_read() {
        let memory = FixedMemory::<RW>::new(0x1000, 0x16);

        // Read from an address out of the reserved memory
        assert_eq!(
            memory.read(0x1020, MemAccessSize::Word),
            Err(MemoryError::InvalidMemoryAccess(0x1020))
        );
    }

    #[test]
    fn test_invalid_write() {
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x16);

        // Write to an address out of the reserved memory
        assert_eq!(
            memory.write(0x1020, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::InvalidMemoryAccess(0x1020))
        );
    }

    #[test]
    fn test_function_read_write_bytes() {
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x16);

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
        let memory = FixedMemory::<WO>::new(0x1000, 0x16);

        // Read from an address in a write-only memory
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Err(MemoryError::UnauthorizedRead(0x1000))
        );

        let memory = FixedMemory::<NA>::new(0x1000, 0x16);

        // Read from an address in a no-access memory
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word),
            Err(MemoryError::UnauthorizedRead(0x1000))
        );
    }

    #[test]
    fn test_unpermitted_write() {
        let mut memory = FixedMemory::<RO>::new(0x1000, 0x16);

        // Write to an address in a read-only memory
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::UnauthorizedWrite(0x1000))
        );

        let mut memory = FixedMemory::<NA>::new(0x1000, 0x16);

        // Write to an address in a no-access memory
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::UnauthorizedWrite(0x1000))
        );
    }

    #[test]
    fn test_memory_size() {
        let mut memory = FixedMemory::<RW>::new(0x1000, 0x100);

        // Initial size should be 0
        assert_eq!(memory.vec.len(), 0);

        // Write a byte at the start of the memory
        memory.write(0x1000, MemAccessSize::Byte, 0xAB).unwrap();
        assert_eq!(memory.vec.len(), 1);

        // Write a byte at an address that would require 2 words
        memory.write(0x1007, MemAccessSize::Byte, 0xCD).unwrap();
        assert_eq!(memory.vec.len(), 2);

        // Write a halfword at an address that would require 3 words
        memory
            .write(0x100A, MemAccessSize::HalfWord, 0xEF12)
            .unwrap();
        assert_eq!(memory.vec.len(), 3);

        // Write a word at an address that would require 5 words
        memory
            .write(0x1010, MemAccessSize::Word, 0x12345678)
            .unwrap();
        assert_eq!(memory.vec.len(), 5);

        // Write a byte at a far address
        memory.write(0x10FF, MemAccessSize::Byte, 0xFF).unwrap();
        assert_eq!(memory.vec.len(), 64);
    }
}
