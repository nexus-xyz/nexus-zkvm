//! ELF File Loader for RISC-V 32-bit Executables
//!
//! This module provides functionality to load and parse ELF (Executable and Linkable Format)
//! files specifically for RISC-V 32-bit architecture. It implements a Harvard architecture
//! model, separating instruction and data memory.
//!
//! # Key Features
//!
//! - Parses RISC-V 32-bit ELF files
//! - Implements Harvard architecture separation (instruction vs data memory)
//! - Supports loading from various sources (files, in-memory bytes)
//! - Extracts program instructions, entry point, base address, and initial memory images
//!
//! # Main Components
//!
//! - `ElfFile`: Struct representing a parsed ELF file, containing:
//!   - Instructions (as 32-bit words)
//!   - Program entry point
//!   - Program base address
//!   - Read-only memory image (ROM)
//!   - Read-write memory image (RAM)
//!
//! - `ElfFile::from_bytes`: Allows creation of `ElfFile` from raw bytes
//! - `ElfFile::from_path`: Allows creation of `ElfFile` from a file path
//!
//! # Usage
//!
//! ```rust
//! use nexus_vm::elf::ElfFile;
//!
//! // Load from raw bytes
//! fn load_elf(elf_data: &[u8]) -> Result<ElfFile, Box<dyn std::error::Error>> {
//!     let elf_file = ElfFile::from_bytes(elf_data)?;
//!     Ok(elf_file)
//! }
//!
//! // Load from file path
//! let elf_file = ElfFile::from_path("test/fib_10.elf");
//! ```
//!
//! # Note
//!
//! This loader is designed for little-endian RISC-V 32-bit executables and implements
//! a Harvard architecture model. Ensure your ELF files are compatible with these specifications.

use crate::{elf::parser, error::VMError, memory::MemorySegmentImage};

use elf::{endian::LittleEndian, ElfBytes};
use std::fs::File;
use std::path::Path;

use super::{error::ParserError, parser::ParsedElfData};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ElfFile {
    /// The instructions of the program encoded as 32-bits.
    pub instructions: Vec<u32>,

    /// The entrypoint of the program.
    pub entry: u32,

    /// The base address of the program.
    pub base: u32,

    /// Initial read only memory image.
    pub rom_image: MemorySegmentImage,

    /// Initial read write memory image containing global and initialized data.
    pub ram_image: MemorySegmentImage,

    /// Nexus-specific metadata embedded in the ELF file.
    pub nexus_metadata: Vec<u32>,
}

impl ElfFile {
    pub fn new(
        instructions: Vec<u32>,
        entry: u32,
        base: u32,
        rom_image: MemorySegmentImage,
        ram_image: MemorySegmentImage,
        nexus_metadata: Vec<u32>,
    ) -> Self {
        ElfFile {
            instructions,
            entry,
            base,
            rom_image,
            ram_image,
            nexus_metadata,
        }
    }

    pub fn get_instructions(&self, address: usize, n: usize) -> Option<&[u32]> {
        let end = address.checked_add(n)?;
        self.instructions.get(address..end)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, VMError> {
        let elf =
            ElfBytes::<LittleEndian>::minimal_parse(data).map_err(Into::<ParserError>::into)?;

        parser::validate_elf_header(&elf.ehdr)?;

        let entry = elf
            .ehdr
            .e_entry
            .try_into()
            .map_err(|_| ParserError::InvalidEntryPointOffset)?;

        let parsed_elf_data: ParsedElfData = parser::parse_segments(&elf, data)?;

        Ok(ElfFile {
            instructions: parsed_elf_data.instructions,
            entry,
            base: parsed_elf_data.base_address as u32,
            rom_image: parsed_elf_data.readonly_memory,
            ram_image: parsed_elf_data.writable_memory,
            nexus_metadata: parsed_elf_data.nexus_metadata,
        })
    }

    pub fn from_path<P: AsRef<Path> + ?Sized>(path: &P) -> Result<Self, VMError> {
        let data = std::fs::read(path).map_err(Into::<ParserError>::into)?;
        Self::from_bytes(&data)
    }
}

#[cfg(test)]
mod tests {
    use nexus_common::constants::ELF_TEXT_START;

    use crate::{memory::MemorySegmentImage, read_testing_elf_from_path};

    use super::*;
    use std::io::Write;

    #[allow(dead_code)]
    fn write_instruction_to_file(instructions: &[u32], file_path: &str) {
        let mut file = File::create(file_path).unwrap();
        for &instruction in instructions {
            file.write_all(&instruction.to_le_bytes()).unwrap();
        }
    }

    #[allow(dead_code)]
    fn write_memory_to_file(memory: &MemorySegmentImage, file_path: &str) {
        let mut file = File::create(file_path).unwrap();
        file.write_all(memory.as_byte_slice()).unwrap();
    }

    #[allow(dead_code)]
    fn debug_elf_file(elf: &ElfFile, file_path: &str) {
        dbg!(elf.instructions.len());
        dbg!(elf.entry);
        dbg!(elf.base);
        dbg!(elf.ram_image.len_bytes());
        dbg!(elf.rom_image.len_bytes());

        // Write elf.instructions to a file
        write_instruction_to_file(&elf.instructions, &format!("{}.inst.bin", file_path));

        // Write elf.memory_image to a file
        write_memory_to_file(&elf.ram_image, &format!("{}.mem.bin", file_path));

        // Write elf.readonly_memory_image to a file
        write_memory_to_file(&elf.rom_image, &format!("{}.rom.bin", file_path));
    }

    #[test]
    fn test_parse_elf_files() {
        // Use llvm-objdump to find what these numbers should be
        const FILE_PATH: &str = "/test/fib_10.elf";
        const ENTRY_POINT: u32 = ELF_TEXT_START;
        const BASE_ADDRESS: u32 = ELF_TEXT_START;
        const NUMBER_OF_INSTRUCTIONS: usize = 1449;

        // Have to use a string literal here due to dumb macro rules.
        let elf = read_testing_elf_from_path!("/test/fib_10.elf");

        assert_eq!(
            elf.entry, ENTRY_POINT,
            "Incorrect entrypoint for {}",
            FILE_PATH
        );
        assert_eq!(
            elf.base, BASE_ADDRESS,
            "Incorrect base address for {}",
            FILE_PATH
        );

        assert_eq!(elf.instructions.len(), NUMBER_OF_INSTRUCTIONS);
    }
}
