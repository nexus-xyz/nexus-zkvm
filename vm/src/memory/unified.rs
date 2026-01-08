//! Unified Memory Interface
//!
//! This module provides a unified memory interface that combines fixed and variable memory types
//! into a single, coherent memory system. It allows for flexible memory configurations with
//! different access modes and address ranges.
//!
//! # Key Components
//!
//! - `UnifiedMemory`: A struct that manages multiple memory regions with different characteristics.
//! - `Modes`: An enum representing different memory access modes (RO, WO, RW, NA).
//!
//! # Features
//!
//! - Combines fixed and variable memory types into a single interface.
//! - Supports multiple memory regions with different access modes.
//! - Provides a unified read/write interface that automatically routes operations to the correct memory type.
//! - Allows adding fixed memory regions with specific base addresses and sizes.
//! - Supports a fallback variable memory for addresses not covered by fixed regions.
//! - Implements display and debug formatting for easy visualization of the memory layout.
//!
//! # Usage
//!
//! ```rust
//! use nexus_vm::memory::{UnifiedMemory, FixedMemory, VariableMemory, MemoryProcessor, MemAccessSize, RO, RW};
//!
//! // Create a new UnifiedMemory
//! let mut memory = UnifiedMemory::default();
//!
//! // Add a read-only fixed memory region
//! memory.add_fixed_ro(FixedMemory::<RO>::new(0x1000, 0x1000)).unwrap();
//!
//! // Add a read-write fixed memory region
//! memory.add_fixed_rw(FixedMemory::<RW>::new(0x2000, 0x1000)).unwrap();
//!
//! // Add a fallback variable memory
//! memory.add_variable(VariableMemory::<RW>::default()).unwrap();
//!
//! // Write to a read-write region
//! memory.write(0x2000, MemAccessSize::Word, 0xABCD1234).unwrap();
//!
//! // Read from a read-only region
//! let value = memory.read(0x1000, MemAccessSize::Word).unwrap();
//!
//! // Access fallback variable memory
//! memory.write(0x5000, MemAccessSize::Byte, 0xFF).unwrap();
//! ```
//!
//! # Memory Layout
//!
//! The unified memory system maintains a layout of different memory regions. This layout
//! is used to determine which type of memory (fixed or variable) and which access mode
//! should be used for a given address.
//!
//! # Error Handling
//!
//! The module uses `Result` types with `MemoryError` for error handling, covering cases such as:
//! - Memory region overlaps
//! - Invalid memory accesses
//! - Unauthorized read/write operations
//!
//! # Testing
//!
//! Comprehensive unit tests are included to verify the correct routing of memory operations
//! to different regions, handling of access permissions, and proper fallback to variable memory.
//!
//! # Performance Considerations
//!
//! The use of `RangeMap` for memory layout allows for efficient lookup of the correct memory
//! region for a given address. However, the performance may vary depending on the number and
//! size of fixed memory regions.
use nexus_common::error::MemoryError;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use rangemap::RangeMap;
use std::{
    collections::BTreeMap,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

use super::{
    FixedMemory, LoadOp, MemAccessSize, MemoryProcessor, StoreOp, VariableMemory, NA, RO, RW, WO,
};

#[derive(Debug, Clone, Eq, PartialEq, FromPrimitive)]
pub enum Modes {
    NA = 0,
    RO = 1,
    WO = 2,
    RW = 3,
}

// nb: we store outside the map becaues `rangemap::RangeMap` does not support a `get_mut` interface (https://github.com/jeffparsons/rangemap/issues/85)
#[derive(Default, Clone)]
pub struct UnifiedMemory {
    // lookup for correct fixed memory, if any
    meta: RangeMap<u32, Modes>,
    // lookup and storage for fixed read-write memories
    frw: RangeMap<u32, usize>,
    pub frw_store: Vec<FixedMemory<RW>>,
    // lookup and storage for fixed read-only memories
    fro: RangeMap<u32, usize>,
    pub fro_store: Vec<FixedMemory<RO>>,
    // lookup and storage for fixed write-only memories
    fwo: RangeMap<u32, usize>,
    pub fwo_store: Vec<FixedMemory<WO>>,
    // lookup and storage for fixed no-access memories
    fna: RangeMap<u32, usize>,
    pub fna_store: Vec<FixedMemory<NA>>,
    // fallback variable read-write memory for all other addresses
    vrw: Option<VariableMemory<RW>>,
}

impl Display for UnifiedMemory {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Display RangeMap table
        writeln!(f, "\nMemory Layout:")?;
        writeln!(f, "┌───────────────┬───────────────┬──────────┐")?;
        writeln!(f, "│  Start Addr   │   End Addr    │  Mode    │")?;
        writeln!(f, "├───────────────┼───────────────┼──────────┤")?;

        for (range, mode) in self.meta.iter() {
            writeln!(
                f,
                "│ 0x{:08x}    │ 0x{:08x}    │ {:<8} │",
                range.start,
                range.end,
                format!("{:?}", mode)
            )?;
        }

        writeln!(f, "└───────────────┴───────────────┴──────────┘")?;

        Ok(())
    }
}

impl Debug for UnifiedMemory {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(self, f)?;

        // Display Fixed Read-Write Memory
        if !self.frw_store.is_empty() {
            writeln!(f, "\nFixed Read-Write Memory:")?;
            for (i, mem) in self.frw_store.iter().enumerate() {
                writeln!(f, "Segment {i}")?;
                writeln!(f, "{mem:?}")?;
            }
        }

        // Display Fixed Read-Only Memory
        if !self.fro_store.is_empty() {
            writeln!(f, "\nFixed Read-Only Memory:")?;
            for (i, mem) in self.fro_store.iter().enumerate() {
                writeln!(f, "Segment {i}")?;
                writeln!(f, "{mem:?}")?;
            }
        }

        // Display Fixed Write-Only Memory
        if !self.fwo_store.is_empty() {
            writeln!(f, "\nFixed Write-Only Memory:")?;
            for (i, mem) in self.fwo_store.iter().enumerate() {
                writeln!(f, "Segment {i}")?;
                writeln!(f, "{mem:?}")?;
            }
        }

        // Display Fixed No-Access Memory
        if !self.fna_store.is_empty() {
            writeln!(f, "\nFixed No-Access Memory:")?;
            for (i, mem) in self.fna_store.iter().enumerate() {
                writeln!(f, "Segment {i}")?;
                writeln!(f, "{mem:?}")?;
            }
        }

        // Display Variable Read-Write Memory
        if let Some(vrw) = &self.vrw {
            writeln!(f, "\nVariable Read-Write Memory:")?;
            write!(f, "{vrw:?}")?;
        }

        Ok(())
    }
}

impl From<VariableMemory<RW>> for UnifiedMemory {
    fn from(vrw: VariableMemory<RW>) -> Self {
        Self {
            meta: RangeMap::new(),
            frw: RangeMap::new(),
            frw_store: Vec::new(),
            fro: RangeMap::new(),
            fro_store: Vec::new(),
            fwo: RangeMap::new(),
            fwo_store: Vec::new(),
            fna: RangeMap::new(),
            fna_store: Vec::new(),
            vrw: Some(vrw),
        }
    }
}

macro_rules! add_fixed {
    ( $func: ident, $map: ident, $store: ident, $mode: ident ) => {
        pub fn $func(&mut self, mem: FixedMemory<$mode>) -> Result<(usize, usize), MemoryError> {
            let rng = std::ops::Range {
                start: mem.base_address,
                end: mem.base_address + mem.max_len as u32,
            };
            if self.meta.overlaps(&rng) {
                return Err(MemoryError::MemoryOverlap);
            }

            // Range<u32> is Copy, so cloning is unnecessary.
            self.meta.insert(rng, Modes::$mode);

            let idx = self.$store.len();
            self.$map.insert(rng, idx);
            self.$store.push(mem);

            Ok((Modes::$mode as usize, idx))
        }
    };
}

impl UnifiedMemory {
    pub fn add_variable(&mut self, vrw: VariableMemory<RW>) -> Result<(), MemoryError> {
        if self.vrw.is_some() {
            return Err(MemoryError::MemoryOverlap);
        }

        self.vrw = Some(vrw);
        Ok(())
    }

    add_fixed!(add_fixed_rw, frw, frw_store, RW);
    add_fixed!(add_fixed_ro, fro, fro_store, RO);
    add_fixed!(add_fixed_wo, fwo, fwo_store, WO);
    add_fixed!(add_fixed_na, fna, fna_store, NA);

    pub fn addr_val_bytes(&self, uidx: (usize, usize)) -> Result<BTreeMap<u32, u8>, MemoryError> {
        let (store, idx) = uidx;

        match FromPrimitive::from_usize(store) {
            Some(Modes::RW) => {
                if idx < self.frw_store.len() {
                    Ok(self.frw_store[idx].addr_val_bytes())
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::RO) => {
                if idx < self.fro_store.len() {
                    Ok(self.fro_store[idx].addr_val_bytes())
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::WO) => {
                if idx < self.fwo_store.len() {
                    Ok(self.fwo_store[idx].addr_val_bytes())
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::NA) => {
                if idx < self.fna_store.len() {
                    Ok(self.fna_store[idx].addr_val_bytes())
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            _ => Err(MemoryError::UndefinedMemoryRegion),
        }
    }

    pub fn segment_words(
        &self,
        uidx: (usize, usize),
        start: u32,
        end: Option<u32>,
    ) -> Result<&[u32], MemoryError> {
        let (store, idx) = uidx;

        match FromPrimitive::from_usize(store) {
            Some(Modes::RW) => {
                if idx < self.frw_store.len() {
                    Ok(self.frw_store[idx].segment_words(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::RO) => {
                if idx < self.fro_store.len() {
                    Ok(self.fro_store[idx].segment_words(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::WO) => {
                if idx < self.fwo_store.len() {
                    Ok(self.fwo_store[idx].segment_words(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::NA) => {
                if idx < self.fna_store.len() {
                    Ok(self.fna_store[idx].segment_words(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            _ => Err(MemoryError::UndefinedMemoryRegion),
        }
    }

    pub fn segment_bytes(
        &self,
        uidx: (usize, usize),
        start: u32,
        end: Option<u32>,
    ) -> Result<&[u8], MemoryError> {
        let (store, idx) = uidx;

        match FromPrimitive::from_usize(store) {
            Some(Modes::RW) => {
                if idx < self.frw_store.len() {
                    Ok(self.frw_store[idx].segment_bytes(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::RO) => {
                if idx < self.fro_store.len() {
                    Ok(self.fro_store[idx].segment_bytes(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::WO) => {
                if idx < self.fwo_store.len() {
                    Ok(self.fwo_store[idx].segment_bytes(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            Some(Modes::NA) => {
                if idx < self.fna_store.len() {
                    Ok(self.fna_store[idx].segment_bytes(start, end))
                } else {
                    Err(MemoryError::UndefinedMemoryRegion)
                }
            }
            _ => Err(MemoryError::UndefinedMemoryRegion),
        }
    }
}

impl MemoryProcessor for UnifiedMemory {
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
        address: u32,
        size: MemAccessSize,
        value: u32,
    ) -> Result<StoreOp, MemoryError> {
        if let Some(meta) = self.meta.get(&address) {
            // Safety: that address is in meta means unwraps and indexing are safe
            match meta {
                Modes::RW => {
                    self.frw_store[*self.frw.get(&address).unwrap()].write(address, size, value)
                }
                Modes::RO => {
                    self.fro_store[*self.fro.get(&address).unwrap()].write(address, size, value)
                }
                Modes::WO => {
                    self.fwo_store[*self.fwo.get(&address).unwrap()].write(address, size, value)
                }
                Modes::NA => {
                    self.fna_store[*self.fna.get(&address).unwrap()].write(address, size, value)
                }
            }
        } else if let Some(mut vrw) = self.vrw.take() {
            // work around lifetime issues
            let ret = vrw.write(address, size, value);
            self.vrw = Some(vrw);

            ret
        } else {
            Err(MemoryError::InvalidMemoryAccess(
                address,
                "writing address not in unified memory",
            ))
        }
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
    fn read(&self, address: u32, size: MemAccessSize) -> Result<LoadOp, MemoryError> {
        if let Some(meta) = self.meta.get(&address) {
            // that address is in meta means unwraps are safe
            match meta {
                Modes::RW => self.frw_store[*self.frw.get(&address).unwrap()].read(address, size),
                Modes::RO => self.fro_store[*self.fro.get(&address).unwrap()].read(address, size),
                Modes::WO => self.fwo_store[*self.fwo.get(&address).unwrap()].read(address, size),
                Modes::NA => self.fna_store[*self.fna.get(&address).unwrap()].read(address, size),
            }
        } else if let Some(vrw) = &self.vrw {
            vrw.read(address, size)
        } else {
            Err(MemoryError::InvalidMemoryAccess(
                address,
                "reading address not in unified memory",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_setup() -> UnifiedMemory {
        let mut memory = UnifiedMemory::default();
        memory
            .add_variable(VariableMemory::<RW>::default())
            .unwrap();

        memory
            .add_fixed_ro(FixedMemory::<RO>::from_word_vec(
                0,
                0x1000,
                vec![0x12EFCDAB; 0x1000],
            ))
            .unwrap();
        memory
            .add_fixed_rw(FixedMemory::<RW>::new(0x1000, 0x1000))
            .unwrap();
        memory
            .add_fixed_wo(FixedMemory::<WO>::new(0x2000, 0x1000))
            .unwrap();
        memory
            .add_fixed_na(FixedMemory::<NA>::new(0x3000, 0x1000))
            .unwrap();

        memory
    }

    #[test]
    fn test_fixed_rw_write_and_read_byte() {
        let mut memory = memory_setup();

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
    fn test_fixed_rw_write_and_read_halfword() {
        let mut memory = memory_setup();

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
    fn test_fixed_rw_write_and_read_word() {
        let mut memory = memory_setup();

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
    fn test_fixed_rw_overwrite() {
        let mut memory = memory_setup();

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
    fn test_fixed_ro_read_byte() {
        let memory = memory_setup();

        // Read bytes
        assert_eq!(
            memory.read(0x0000, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x0000, 0xAB))
        );
        assert_eq!(
            memory.read(0x0001, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x0001, 0xCD))
        );
        assert_eq!(
            memory.read(0x0002, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x0002, 0xEF))
        );
        assert_eq!(
            memory.read(0x0003, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x0003, 0x12))
        );

        // Read the whole word
        assert_eq!(
            memory.read(0x0000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x0000, 0x12EFCDAB))
        );
    }

    #[test]
    fn test_fixed_ro_read_halfword() {
        let memory = memory_setup();

        // Read halfwords
        assert_eq!(
            memory.read(0x0000, MemAccessSize::HalfWord),
            Ok(LoadOp::Op(MemAccessSize::HalfWord, 0x0000, 0xCDAB))
        );
        assert_eq!(
            memory.read(0x0002, MemAccessSize::HalfWord),
            Ok(LoadOp::Op(MemAccessSize::HalfWord, 0x0002, 0x12EF))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x0001, MemAccessSize::HalfWord),
            Err(MemoryError::UnalignedMemoryRead(0x0001))
        );
    }

    #[test]
    fn test_fixed_ro_read_word() {
        let memory = memory_setup();

        // Read the word
        assert_eq!(
            memory.read(0x0000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x0000, 0x12EFCDAB))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x0001, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x0001))
        );
        assert_eq!(
            memory.read(0x0002, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x0002))
        );
        assert_eq!(
            memory.read(0x0003, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x0003))
        );
    }

    #[test]
    fn test_fixed_ro_unpermitted_write() {
        let mut memory = memory_setup();

        // Write to an address in a read-only memory
        assert_eq!(
            memory.write(0x0000, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::UnauthorizedWrite(0x0000))
        );
    }

    #[test]
    fn test_fixed_wo_write_byte() {
        let mut memory = memory_setup();

        // Write bytes at different alignments
        assert_eq!(
            memory.write(0x2000, MemAccessSize::Byte, 0xAB),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x2000, 0xAB, 0x00))
        );
        assert_eq!(
            memory.write(0x2001, MemAccessSize::Byte, 0xCD),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x2001, 0xCD, 0x00))
        );
        assert_eq!(
            memory.write(0x2002, MemAccessSize::Byte, 0xEF),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x2002, 0xEF, 0x00))
        );
        assert_eq!(
            memory.write(0x2003, MemAccessSize::Byte, 0x12),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x2003, 0x12, 0x00))
        );
    }

    #[test]
    fn test_fixed_wo_write_halfword() {
        let mut memory = memory_setup();

        // Write halfwords at aligned addresses
        assert_eq!(
            memory.write(0x2000, MemAccessSize::HalfWord, 0xABCD),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x2000, 0xABCD, 0x0000)),
        );
        assert_eq!(
            memory.write(0x2002, MemAccessSize::HalfWord, 0xEF12),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x2002, 0xEF12, 0x0000)),
        );

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x2001, MemAccessSize::HalfWord, 0x3456),
            Err(MemoryError::UnalignedMemoryWrite(0x2001))
        );
    }

    #[test]
    fn test_fixed_wo_write_word() {
        let mut memory = memory_setup();

        // Write a word at an aligned address
        assert_eq!(
            memory.write(0x2000, MemAccessSize::Word, 0xABCD1234),
            Ok(StoreOp::Op(
                MemAccessSize::Word,
                0x2000,
                0xABCD1234,
                0x00000000
            )),
        );

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x2001, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x2001))
        );
        assert_eq!(
            memory.write(0x2002, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x2002))
        );
        assert_eq!(
            memory.write(0x2003, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x2003))
        );
    }

    #[test]
    fn test_fixed_wo_overwrite() {
        let mut memory = memory_setup();

        // Write a word
        assert_eq!(
            memory.write(0x2000, MemAccessSize::Word, 0xABCD1234),
            Ok(StoreOp::Op(
                MemAccessSize::Word,
                0x2000,
                0xABCD1234,
                0x00000000
            )),
        );

        // Overwrite with bytes
        assert_eq!(
            memory.write(0x2000, MemAccessSize::Byte, 0xEF),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x2000, 0xEF, 0x34))
        );
        assert_eq!(
            memory.write(0x2001, MemAccessSize::Byte, 0x56),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x2001, 0x56, 0x12))
        );

        // Overwrite with a halfword
        assert_eq!(
            memory.write(0x2002, MemAccessSize::HalfWord, 0x7890),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x2002, 0x7890, 0xABCD)),
        );
    }

    #[test]
    fn test_fixed_wo_unpermitted_read() {
        let mut memory = memory_setup();

        memory
            .write(0x2000, MemAccessSize::Word, 0xABCD1234)
            .unwrap();

        // Read from an address in a write-only memory
        assert_eq!(
            memory.read(0x2000, MemAccessSize::Word),
            Err(MemoryError::UnauthorizedRead(0x2000))
        );
    }

    #[test]
    fn test_fixed_no_unpermitted_write() {
        let mut memory = memory_setup();

        // Write to an address in a no-access memory
        assert_eq!(
            memory.write(0x3000, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::UnauthorizedWrite(0x3000))
        );
    }

    #[test]
    fn test_fixed_no_unpermitted_read() {
        let memory = memory_setup();

        // Read from an address in a no-access memory
        assert_eq!(
            memory.read(0x3000, MemAccessSize::Word),
            Err(MemoryError::UnauthorizedRead(0x3000))
        );
    }

    #[test]
    fn test_variable_write_and_read_byte() {
        let mut memory = memory_setup();

        // Write bytes at different alignments
        assert_eq!(
            memory.write(0x4000, MemAccessSize::Byte, 0xAB),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x4000, 0xAB, 0x00))
        );
        assert_eq!(
            memory.write(0x4001, MemAccessSize::Byte, 0xCD),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x4001, 0xCD, 0x00))
        );
        assert_eq!(
            memory.write(0x4002, MemAccessSize::Byte, 0xEF),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x4002, 0xEF, 0x00))
        );
        assert_eq!(
            memory.write(0x4003, MemAccessSize::Byte, 0x12),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x4003, 0x12, 0x00))
        );

        // Read bytes
        assert_eq!(
            memory.read(0x4000, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x4000, 0xAB))
        );
        assert_eq!(
            memory.read(0x4001, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x4001, 0xCD))
        );
        assert_eq!(
            memory.read(0x4002, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x4002, 0xEF))
        );
        assert_eq!(
            memory.read(0x4003, MemAccessSize::Byte),
            Ok(LoadOp::Op(MemAccessSize::Byte, 0x4003, 0x12))
        );

        // Read the whole word
        assert_eq!(
            memory.read(0x4000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x4000, 0x12EFCDAB))
        );
    }

    #[test]
    fn test_variable_write_and_read_halfword() {
        let mut memory = memory_setup();

        // Write halfwords at aligned addresses
        assert_eq!(
            memory.write(0x4000, MemAccessSize::HalfWord, 0xABCD),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x4000, 0xABCD, 0x0000)),
        );
        assert_eq!(
            memory.write(0x4002, MemAccessSize::HalfWord, 0xEF12),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x4002, 0xEF12, 0x0000)),
        );

        // Read halfwords
        assert_eq!(
            memory.read(0x4000, MemAccessSize::HalfWord),
            Ok(LoadOp::Op(MemAccessSize::HalfWord, 0x4000, 0xABCD))
        );
        assert_eq!(
            memory.read(0x4002, MemAccessSize::HalfWord),
            Ok(LoadOp::Op(MemAccessSize::HalfWord, 0x4002, 0xEF12))
        );

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x4001, MemAccessSize::HalfWord, 0x3456),
            Err(MemoryError::UnalignedMemoryWrite(0x4001))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x4001, MemAccessSize::HalfWord),
            Err(MemoryError::UnalignedMemoryRead(0x4001))
        );
    }

    #[test]
    fn test_variable_write_and_read_word() {
        let mut memory = memory_setup();

        // Write a word at an aligned address
        assert_eq!(
            memory.write(0x4000, MemAccessSize::Word, 0xABCD1234),
            Ok(StoreOp::Op(
                MemAccessSize::Word,
                0x4000,
                0xABCD1234,
                0x00000000
            )),
        );

        // Read the word
        assert_eq!(
            memory.read(0x4000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x4000, 0xABCD1234))
        );

        // Write to an unaligned address
        assert_eq!(
            memory.write(0x4001, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x4001))
        );
        assert_eq!(
            memory.write(0x4002, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x4002))
        );
        assert_eq!(
            memory.write(0x4003, MemAccessSize::Word, 0xEF678901),
            Err(MemoryError::UnalignedMemoryWrite(0x4003))
        );

        // Read from an unaligned address
        assert_eq!(
            memory.read(0x4001, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x4001))
        );
        assert_eq!(
            memory.read(0x4002, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x4002))
        );
        assert_eq!(
            memory.read(0x4003, MemAccessSize::Word),
            Err(MemoryError::UnalignedMemoryRead(0x4003))
        );
    }

    #[test]
    fn test_variable_overwrite() {
        let mut memory = memory_setup();

        // Write a word
        assert_eq!(
            memory.write(0x4000, MemAccessSize::Word, 0xABCD1234),
            Ok(StoreOp::Op(
                MemAccessSize::Word,
                0x4000,
                0xABCD1234,
                0x00000000
            )),
        );

        // Overwrite with bytes
        assert_eq!(
            memory.write(0x4000, MemAccessSize::Byte, 0xEF),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x4000, 0xEF, 0x34))
        );
        assert_eq!(
            memory.write(0x4001, MemAccessSize::Byte, 0x56),
            Ok(StoreOp::Op(MemAccessSize::Byte, 0x4001, 0x56, 0x12))
        );
        assert_eq!(
            memory.read(0x4000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x4000, 0xABCD56EF))
        );

        // Overwrite with a halfword
        assert_eq!(
            memory.write(0x4002, MemAccessSize::HalfWord, 0x7890),
            Ok(StoreOp::Op(MemAccessSize::HalfWord, 0x4002, 0x7890, 0xABCD)),
        );
        assert_eq!(
            memory.read(0x4000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x4000, 0x789056EF))
        );
    }

    #[test]
    fn test_variable_invalid_read() {
        let memory = memory_setup();

        // Read from an uninitialized address
        assert_eq!(
            memory.read(0x4000, MemAccessSize::Word),
            Ok(LoadOp::Op(MemAccessSize::Word, 0x4000, 0x00000000))
        );
    }

    #[test]
    fn test_no_variable_write() {
        let mut memory = UnifiedMemory::default();

        // Write non-existent unified memory
        assert_eq!(
            memory.write(0x4000, MemAccessSize::Word, 0xABCD1234),
            Err(MemoryError::InvalidMemoryAccess(
                0x4000,
                "writing address not in unified memory",
            ))
        );
    }
}
