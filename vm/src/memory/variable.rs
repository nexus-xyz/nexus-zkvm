use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomData;

use crate::WORD_SIZE;
use nexus_common::error::MemoryError;

use super::{LoadOp, MemAccessSize, MemoryProcessor, Mode, StoreOp, RO, RW, WO};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct VariableMemory<M: Mode>(BTreeMap<u32, u32>, PhantomData<M>);

impl<M: Mode> From<BTreeMap<u32, u32>> for VariableMemory<M> {
    fn from(map: BTreeMap<u32, u32>) -> Self {
        VariableMemory::<M>(map, PhantomData)
    }
}

impl<M: Mode> Debug for VariableMemory<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "┌─────────────────────────────────────┐")?;
        writeln!(f, "│         Variable Memory             │")?;
        writeln!(f, "├───────────────────┬─────────────────┤")?;
        writeln!(f, "│     Address       │      Value      │")?;
        writeln!(f, "├───────────────────┼─────────────────┤")?;

        for (&address, &value) in self.0.iter() {
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

        let prev_value = self
            .0
            .get(&aligned_address) // Align to word boundary
            .map(|&value| ((value >> shift) & mask))
            .unwrap_or(0);

        let value = self
            .0
            .entry(aligned_address) // Align to word boundary
            .and_modify(|e| *e = (*e & write_mask) | data)
            .or_insert(data);

        Ok(StoreOp::Op(
            size,
            address,
            (*value >> shift) & mask,
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
    fn execute_read(&self, address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        let (shift, mask) = size.get_shift_and_mask(address);

        if !size.is_aligned(address) {
            return Err(MemoryError::UnalignedMemoryRead(address));
        }

        // Align to word boundary
        let aligned_address = address & !(WORD_SIZE - 1) as u32;

        let value = self
            .0
            .get(&aligned_address) // Align to word boundary
            .map(|&value| ((value >> shift) & mask))
            .ok_or(MemoryError::InvalidMemoryAccess(address))?;

        Ok(LoadOp::Op(size, address, value))
    }
    /// Returns a slice of memory between start and end addresses, if they form a contiguous segment.
    pub fn segment(&self, start: u32, end: Option<u32>) -> Result<Vec<u32>, MemoryError> {
        // Check if start is valid
        if !self.0.contains_key(&start) {
            return Err(MemoryError::InvalidMemorySegment);
        }

        // Check if end is valid (if provided)
        if let Some(end) = end {
            if end < start || !self.0.contains_key(&end) {
                return Err(MemoryError::InvalidMemorySegment);
            }
        }

        let mut values = Vec::new();
        let mut current = start;

        loop {
            if let Some(value) = self.0.get(&current) {
                values.push(*value);

                if let Some(end) = end {
                    if current >= end {
                        break;
                    }
                }

                current += WORD_SIZE as u32;
            } else if end.is_none() {
                break;
            } else {
                // If we can't find the next contiguous address, it's an invalid segment
                return Err(MemoryError::InvalidMemorySegment);
            }
        }

        if values.is_empty() {
            Err(MemoryError::InvalidMemorySegment)
        } else {
            Ok(values)
        }
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
    fn test_invalid_read() {
        let memory = VariableMemory::<RW>::default();

        // Read from an uninitialized address
        assert_eq!(
            memory.read(0x2000, MemAccessSize::Word),
            Err(MemoryError::InvalidMemoryAccess(0x2000))
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

        let memory = VariableMemory::<WO>::from(map);

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
