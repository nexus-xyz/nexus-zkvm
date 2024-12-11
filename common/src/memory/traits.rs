use crate::error::MemoryError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Represents the size of memory access operations.
pub enum MemAccessSize {
    Byte = 1,
    HalfWord = 2,
    Word = 4,
}

impl MemAccessSize {
    // Helper function to get shift and mask for different access sizes
    pub fn get_shift_and_mask(&self, address: u32) -> (u32, u32) {
        match self {
            MemAccessSize::Byte => ((address & 0x3) * 8, 0xff),
            MemAccessSize::HalfWord => ((address & 0x2) * 8, 0xffff),
            MemAccessSize::Word => (0, 0xffffffff),
        }
    }

    // Helper function to check if the input address is aligned or not
    pub fn is_aligned(&self, address: u32) -> bool {
        match self {
            MemAccessSize::Byte => true,
            MemAccessSize::HalfWord => address & 0x1 == 0,
            MemAccessSize::Word => address & 0x3 == 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryRecord {
    // (size, address, value), timestamp, prev_timestamp
    LoadRecord((MemAccessSize, u32, u32), u32, u32),
    // (size, address, value, prev_value), timestamp, prev_timestamp
    StoreRecord((MemAccessSize, u32, u32, u32), u32, u32),
}
pub type MemoryRecords = HashSet<MemoryRecord>;

impl MemoryRecord {
    pub fn get_timestamp(&self) -> u32 {
        match self {
            MemoryRecord::LoadRecord((_, _, _), timestamp, _) => *timestamp,
            MemoryRecord::StoreRecord((_, _, _, _), timestamp, _) => *timestamp,
        }
    }

    pub fn get_prev_timestamp(&self) -> u32 {
        match self {
            MemoryRecord::LoadRecord((_, _, _), _, prev_timestamp) => *prev_timestamp,
            MemoryRecord::StoreRecord((_, _, _, _), _, prev_timestamp) => *prev_timestamp,
        }
    }

    pub fn get_address(&self) -> u32 {
        match self {
            MemoryRecord::LoadRecord((_, address, _), _, _) => *address,
            MemoryRecord::StoreRecord((_, address, _, _), _, _) => *address,
        }
    }

    pub fn get_value(&self) -> u32 {
        match self {
            MemoryRecord::LoadRecord((_, _, value), _, _) => *value,
            MemoryRecord::StoreRecord((_, _, value, _), _, _) => *value,
        }
    }

    pub fn get_prev_value(&self) -> Option<u32> {
        match self {
            MemoryRecord::LoadRecord((_, _, _), _, _) => None,
            MemoryRecord::StoreRecord((_, _, _, prev_value), _, _) => Some(*prev_value),
        }
    }

    pub fn get_size(&self) -> MemAccessSize {
        match self {
            MemoryRecord::LoadRecord((size, _, _), _, _) => *size,
            MemoryRecord::StoreRecord((size, _, _, _), _, _) => *size,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum LoadOp {
    Op(MemAccessSize, u32, u32), // size, address, value
}
pub type LoadOps = HashSet<LoadOp>;

impl From<LoadOp> for LoadOps {
    fn from(op: LoadOp) -> Self {
        let mut ops = LoadOps::new();
        ops.insert(op);

        ops
    }
}

impl LoadOp {
    pub fn as_record(self, timestamp: usize, prev_timestamp: usize) -> MemoryRecord {
        match self {
            Self::Op(size, address, value) => MemoryRecord::LoadRecord(
                (size, address, value),
                timestamp as u32,
                prev_timestamp as u32,
            ),
        }
    }

    pub fn get_address(&self) -> u32 {
        match self {
            Self::Op(_, address, _) => *address,
        }
    }

    pub fn get_value(&self) -> u32 {
        match self {
            Self::Op(_, _, value) => *value,
        }
    }

    pub fn get_size(&self) -> MemAccessSize {
        match self {
            Self::Op(size, _, _) => *size,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StoreOp {
    Op(MemAccessSize, u32, u32, u32), // size, address, value, prev_value
}
pub type StoreOps = HashSet<StoreOp>;

impl From<StoreOp> for StoreOps {
    fn from(op: StoreOp) -> Self {
        let mut ops = StoreOps::new();
        ops.insert(op);

        ops
    }
}

impl StoreOp {
    pub fn as_record(self, timestamp: usize, prev_timestamp: usize) -> MemoryRecord {
        match self {
            Self::Op(size, address, value, prev_value) => MemoryRecord::StoreRecord(
                (size, address, value, prev_value),
                timestamp as u32,
                prev_timestamp as u32,
            ),
        }
    }

    pub fn get_address(&self) -> u32 {
        match self {
            Self::Op(_, address, _, _) => *address,
        }
    }

    pub fn get_value(&self) -> u32 {
        match self {
            Self::Op(_, _, value, _) => *value,
        }
    }

    pub fn get_prev_value(&self) -> u32 {
        match self {
            Self::Op(_, _, _, prev_value) => *prev_value,
        }
    }

    pub fn get_size(&self) -> MemAccessSize {
        match self {
            Self::Op(size, _, _, _) => *size,
        }
    }
}

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
    fn read(&self, address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError>;

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
    fn write(
        &mut self,
        address: u32,
        size: MemAccessSize,
        value: u32,
    ) -> Result<StoreOp, MemoryError>;

    /// Reads multiple bytes from memory at the specified address, built on top of `read`.
    ///
    /// Only used for (unproven) ecalls, so does not return an operation record.
    fn read_bytes(&self, address: u32, size: usize) -> Result<Vec<u8>, MemoryError> {
        let mut data = vec![0; size];
        for (i, byte) in data.iter_mut().enumerate().take(size) {
            match self.read(address + i as u32, MemAccessSize::Byte)? {
                LoadOp::Op(_, _, v) => *byte = v as u8,
            };
        }
        Ok(data)
    }

    /// Writes multiple bytes to memory at the specified address, built on top of `write`.
    ///
    /// Only used for (unproven) ecalls, so does not return an operation record.
    fn write_bytes(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryError> {
        for (i, &byte) in data.iter().enumerate() {
            self.write(address + i as u32, MemAccessSize::Byte, byte as u32)?;
        }
        Ok(())
    }
}
