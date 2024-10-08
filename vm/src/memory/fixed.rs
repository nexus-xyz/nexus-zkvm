use nexus_common::error::MemoryError;

use super::{get_shift_and_mask, MemAccessSize, MemoryProcessor};

#[derive(Debug, Default)]
pub struct FixedMemory {
    max_len: usize,
    vec: Vec<u32>,
}

impl FixedMemory {
    pub fn new(max_len: usize) -> Self {
        Self {
            max_len,
            vec: Vec::<u32>::new(),
        }
    }

    pub fn from_vec(max_len: usize, vec: Vec<u32>) -> Self {
        vec.to_owned().truncate(max_len);

        Self { max_len, vec }
    }

    pub fn segment(&self, start: usize, end: Option<usize>) -> &[u32] {
        if let Some(e) = end {
            &self.vec[start..e]
        } else {
            &self.vec[start..]
        }
    }
}

impl MemoryProcessor for FixedMemory {
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
    fn write(&mut self, address: u32, size: MemAccessSize, value: u32) -> Result<u32, MemoryError> {
        let (shift, mask) = get_shift_and_mask(size, address);

        // Check for alignment
        if address & size as u32 != 0 {
            return Err(MemoryError::UnalignedMemoryWrite(address));
        }

        // Error if address is outside reserved space
        if address >= self.max_len as u32 {
            return Err(MemoryError::InvalidMemoryAccess(address));
        }

        // Align to word boundary
        let aligned_address = (address & !0x3) as usize;
        let write_mask = !(mask << shift);
        let data = (value & mask) << shift;

        if self.vec.len() < aligned_address {
            self.vec.resize_with(1 + aligned_address, Default::default);
            self.vec[aligned_address] = data;
        } else {
            self.vec[aligned_address] &= write_mask;
            self.vec[aligned_address] |= data;
        }

        Ok((data >> shift) & mask)
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
    fn read(&self, address: u32, size: MemAccessSize) -> Result<u32, MemoryError> {
        let (shift, mask) = get_shift_and_mask(size, address);

        if address & size as u32 != 0 {
            return Err(MemoryError::UnalignedMemoryRead(address));
        }

        // Error if address is outside reserved space
        if address >= self.max_len as u32 {
            return Err(MemoryError::InvalidMemoryAccess(address));
        }

        // Align to word boundary
        let aligned_address = (address & !0x3) as usize;

        if self.vec.len() < aligned_address {
            return Ok(u32::default());
        }

        Ok((self.vec[aligned_address] >> shift) & mask)
    }

    fn read_bytes(&self, address: u32, size: usize) -> Result<Vec<u8>, MemoryError> {
        let mut data = vec![0; size];
        for (i, byte) in data.iter_mut().enumerate().take(size) {
            *byte = self.read(address + i as u32, MemAccessSize::Byte)? as u8;
        }
        Ok(data)
    }

    fn write_bytes(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryError> {
        for (i, &byte) in data.iter().enumerate() {
            self.write(address + i as u32, MemAccessSize::Byte, byte as u32)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use nexus_common::error::MemoryError;

    use super::*;

    #[test]
    fn test_write_and_read_byte() {
        let mut memory = FixedMemory::new(0x100000);

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
        let mut memory = FixedMemory::new(0x100000);

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
        let mut memory = FixedMemory::new(0x100000);

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
        let mut memory = FixedMemory::new(0x100000);

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
        let memory = FixedMemory::new(0x100000);

        // Read from an address out of the reserved memory
        assert_eq!(
            memory.read(0x100004, MemAccessSize::Word),
            Err(MemoryError::InvalidMemoryAccess(0x100004))
        );
    }

    #[test]
    fn test_invalid_write() {
        let mut memory = FixedMemory::new(0x100000);

        // Write to an address out of the reserved memory
        assert_eq!(
            memory.write(0x100004, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::InvalidMemoryAccess(0x100004))
        );
    }

    #[test]
    fn test_function_read_write_bytes() {
        let mut memory = FixedMemory::new(0x10000);

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
        assert_eq!(memory.read(0x1002, MemAccessSize::Byte), Ok(0x11));
        assert_eq!(memory.read(0x1003, MemAccessSize::Byte), Ok(0x22));
        assert_eq!(memory.read(0x1004, MemAccessSize::Byte), Ok(0x33));
        assert_eq!(memory.read(0x1005, MemAccessSize::Byte), Ok(0x44));

        // Test reading words after write_bytes
        assert_eq!(memory.read(0x1000, MemAccessSize::Word), Ok(0x2211BBAA));
        assert_eq!(memory.read(0x1004, MemAccessSize::Word), Ok(0x66554433));
    }
}
