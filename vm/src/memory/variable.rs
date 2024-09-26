use std::collections::BTreeMap;

use crate::error::{Result, VMError};

use super::{get_shift_and_mask, MemAccessSize, MemoryProcessor};

#[derive(Debug, Default)]
pub struct VariableMemory(BTreeMap<u32, u32>);

impl From<BTreeMap<u32, u32>> for VariableMemory {
    fn from(map: BTreeMap<u32, u32>) -> Self {
        Self(map)
    }
}

impl MemoryProcessor for VariableMemory {
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
    fn write(&mut self, address: u32, size: MemAccessSize, value: u32) -> Result<u32> {
        let (shift, mask) = get_shift_and_mask(size, address);

        // Check for alignment
        if address & size as u32 != 0 {
            return Err(VMError::UnalignedMemoryWrite(address));
        }

        // Align to word boundary
        let aligned_address = address & !0x3;
        let write_mask = !(mask << shift);
        let data = (value & mask) << shift;

        let value = self
            .0
            .entry(aligned_address) // Align to word boundary
            .and_modify(|e| *e = (*e & write_mask) | data)
            .or_insert(data);

        Ok((*value >> shift) & mask)
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
    fn read(&self, address: u32, size: MemAccessSize) -> Result<u32> {
        let (shift, mask) = get_shift_and_mask(size, address);

        if address & size as u32 != 0 {
            return Err(VMError::UnalignedMemoryRead(address));
        }

        // Align to word boundary
        let aligned_address = address & !0x3;

        self.0
            .get(&aligned_address) // Align to word boundary
            .map(|&value| (value >> shift & mask))
            .ok_or(VMError::InvalidMemoryAccess(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_byte() {
        let mut memory = VariableMemory::default();

        // Write bytes at different alignments
        assert_eq!(memory.write(0x1000, MemAccessSize::Byte, 0xAB), Ok(0xAB));
        assert_eq!(memory.write(0x1001, MemAccessSize::Byte, 0xCD), Ok(0xCD));
        assert_eq!(memory.write(0x1002, MemAccessSize::Byte, 0xEF), Ok(0xEF));
        assert_eq!(memory.write(0x1003, MemAccessSize::Byte, 0x12), Ok(0x12));

        // Read bytes
        assert_eq!(memory.read(0x1000, MemAccessSize::Byte), Ok(0xAB));
        assert_eq!(memory.read(0x1001, MemAccessSize::Byte), Ok(0xCD));
        assert_eq!(memory.read(0x1002, MemAccessSize::Byte), Ok(0xEF));
        assert_eq!(memory.read(0x1003, MemAccessSize::Byte), Ok(0x12));

        // Read the whole word
        assert_eq!(memory.read(0x1000, MemAccessSize::Word), Ok(0x12EFCDAB));
    }

    #[test]
    fn test_write_and_read_halfword() {
        let mut memory = VariableMemory::default();

        // Write halfwords at aligned addresses
        assert_eq!(
            memory.write(0x1000, MemAccessSize::HalfWord, 0xABCD),
            Ok(0xABCD)
        );
        assert_eq!(
            memory.write(0x1002, MemAccessSize::HalfWord, 0xEF12),
            Ok(0xEF12)
        );

        // Read halfwords
        assert_eq!(memory.read(0x1000, MemAccessSize::HalfWord), Ok(0xABCD));
        assert_eq!(memory.read(0x1002, MemAccessSize::HalfWord), Ok(0xEF12));

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x1001, MemAccessSize::HalfWord, 0x3456),
            Err(VMError::UnalignedMemoryWrite(0x1001))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x1001, MemAccessSize::HalfWord),
            Err(VMError::UnalignedMemoryRead(0x1001))
        );
    }

    #[test]
    fn test_write_and_read_word() {
        let mut memory = VariableMemory::default();

        // Write a word at an aligned address
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Ok(0xABCD1234)
        );

        // Read the word
        assert_eq!(memory.read(0x1000, MemAccessSize::Word), Ok(0xABCD1234));

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x1001, MemAccessSize::Word, 0xEF678901),
            Err(VMError::UnalignedMemoryWrite(0x1001))
        );
        assert_eq!(
            memory.write(0x1002, MemAccessSize::Word, 0xEF678901),
            Err(VMError::UnalignedMemoryWrite(0x1002))
        );
        assert_eq!(
            memory.write(0x1003, MemAccessSize::Word, 0xEF678901),
            Err(VMError::UnalignedMemoryWrite(0x1003))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x1001, MemAccessSize::Word),
            Err(VMError::UnalignedMemoryRead(0x1001))
        );
        assert_eq!(
            memory.read(0x1002, MemAccessSize::Word),
            Err(VMError::UnalignedMemoryRead(0x1002))
        );
        assert_eq!(
            memory.read(0x1003, MemAccessSize::Word),
            Err(VMError::UnalignedMemoryRead(0x1003))
        );
    }

    #[test]
    fn test_overwrite() {
        let mut memory = VariableMemory::default();

        // Write a word
        assert_eq!(
            memory.write(0x1000, MemAccessSize::Word, 0xABCD1234),
            Ok(0xABCD1234)
        );

        // Overwrite with bytes
        assert_eq!(memory.write(0x1000, MemAccessSize::Byte, 0xEF), Ok(0xEF));
        assert_eq!(memory.write(0x1001, MemAccessSize::Byte, 0x56), Ok(0x56));
        assert_eq!(memory.read(0x1000, MemAccessSize::Word), Ok(0xABCD56EF));

        // Overwrite with a halfword
        assert_eq!(
            memory.write(0x1002, MemAccessSize::HalfWord, 0x7890),
            Ok(0x7890)
        );
        assert_eq!(memory.read(0x1000, MemAccessSize::Word), Ok(0x789056EF));
    }

    #[test]
    fn test_invalid_read() {
        let memory = VariableMemory::default();

        // Read from an uninitialized address
        assert_eq!(
            memory.read(0x2000, MemAccessSize::Word),
            Err(VMError::InvalidMemoryAccess(0x2000))
        );
    }
}
