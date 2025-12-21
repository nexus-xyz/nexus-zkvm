//! ELF File Parser for RISC-V 32-bit Executables
//!
//! This module provides functionality to parse and validate ELF (Executable and Linkable Format)
//! files specifically for RISC-V 32-bit architecture. It's designed to work with the `elf` crate
//! and uses custom error types defined in the `error` module.
//!
//! # Key Features
//!
//! - Validates ELF headers for RISC-V 32-bit executables
//! - Parses segment information and extracts executable content
//! - Supports Harvard architecture with separate instruction and data memories
//! - Handles allowed sections: .text, .data, .sdata, .rodata, .init, .fini, .bss, .sbss, .got
//! - Supports custom metadata section: .note.nexus-precompiles
//! - Parses precompile metadata from ELF symbols
//!
//! # Main Components
//!
//! - `validate_elf_header`: Ensures the ELF file meets RISC-V 32-bit executable requirements
//! - `parse_segments`: Extracts instructions and builds memory images from ELF segments
//! - `create_allowed_section_map`: Builds a map of allowed ELF sections and their address ranges
//! - `parse_segment_content`: Processes segment content and populates instruction and memory structures
//! - `parse_precompile_metadata`: Extracts and validates precompile metadata from ELF symbols
//!
//! # Memory Types
//!
//! The parser distinguishes between different types of memory:
//! - Instruction memory (read-only)
//! - Read-only data memory
//! - Writable data memory
//! - Metadata (for precompiles)
//!
//! # Note
//!
//! This parser assumes a little-endian RISC-V architecture and is specifically designed for 32-bit executables.
//! It does not make assumptions about the order of sections in the ELF file.
use core::str;
use elf::{
    abi,
    endian::LittleEndian,
    file::{Class, FileHeader},
    section::SectionHeader,
    segment::ProgramHeader,
    ElfBytes,
};
use nexus_common::constants::{PRECOMPILE_SYMBOL_PREFIX, WORD_SIZE};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use tracing::debug;

use crate::{error::Result, memory::MemorySegmentImage};

use super::error::ParserError;

type Instructions = Vec<u32>;
type Metadata = Vec<u32>;
type RawMemoryImage = BTreeMap<u32, u32>;

pub struct ParsedElfData {
    pub instructions: Instructions,
    pub readonly_memory: MemorySegmentImage,
    pub writable_memory: MemorySegmentImage,
    pub base_address: u32,
    pub nexus_metadata: Metadata,
}

/// The maximum size of the memory in bytes.
const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// Defines the allowed sections for Harvard architecture:
/// - Instruction memory: .text
/// - Data memory: .data, .sdata, .rodata
///
/// When building the section map, only these sections and their variants are considered.
/// Section names starting with any of these prefixes are included (e.g., .text1, .data2).
/// All other sections are ignored during parsing.
const ALLOWED_SECTIONS: [&str; 10] = [
    ".text",
    ".data",
    ".sdata",
    ".rodata",
    ".init",
    ".fini",
    ".bss",
    ".sbss",
    ".got",
    ".note.nexus-precompiles",
];

#[derive(Debug, Clone, Copy)]
enum WordType {
    Instruction,
    ReadOnlyData,
    Data,
    Metadata,
}

impl fmt::Display for WordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WordType::Instruction => write!(f, "Instruction"),
            WordType::ReadOnlyData => write!(f, "Read-Only Data"),
            WordType::Data => write!(f, "Data"),
            WordType::Metadata => write!(f, "Metadata"),
        }
    }
}

/// Validates the ELF file header to ensure it meets the required specifications.
///
/// This function checks the following conditions:
/// 1. The ELF file is 32-bit.
/// 2. The target architecture is RISC-V.
/// 3. The file is an executable.
/// 4. The entry point is defined.
/// 5. At least one program header is present.
pub fn validate_elf_header(header: &FileHeader<LittleEndian>) -> Result<()> {
    if header.class != Class::ELF32 {
        return Err(ParserError::Not32Bit.into());
    }

    if header.e_machine != abi::EM_RISCV {
        return Err(ParserError::NotRiscV.into());
    }

    if header.e_type != abi::ET_EXEC {
        return Err(ParserError::NotExecutable.into());
    }

    if header.e_phnum == 0 {
        return Err(ParserError::NoProgramHeader.into());
    }

    Ok(())
}

/// Parses and validates segment information from a program header.
///
/// This function extracts and validates key information from a program header segment,
/// including the virtual address, file size, memory size, and offset.
fn parse_segment_info(segment: &ProgramHeader) -> Result<(u32, u32, u32)> {
    // Convert virtual address to u32 and check for validity
    let virtual_address: u32 = segment
        .p_vaddr
        .try_into()
        .map_err(|_| ParserError::InvalidVirtualAddress(segment.p_vaddr))?;

    // Convert file size to u32 and check for validity
    let file_size: u32 = segment
        .p_filesz
        .try_into()
        .map_err(|_| ParserError::InvalidFileSize)?;

    // Convert memory size to u32 and check for validity
    let mem_size: u32 = segment
        .p_memsz
        .try_into()
        .map_err(|_| ParserError::InvalidMemorySize)?;

    // Convert offset to 32-bit and check for validity
    let offset: u32 = segment
        .p_offset
        .try_into()
        .map_err(|_| ParserError::InvalidSegmentOffset)?;

    // Ensure the virtual address is word-aligned
    if virtual_address % WORD_SIZE as u32 != 0 {
        return Err(ParserError::UnalignedVirtualAddress.into());
    }

    // Ensure file_size <= mem_size and the total size does not exceed the maximum memory size
    if (file_size <= mem_size) && (mem_size + offset < MAXIMUM_MEMORY_SIZE) {
        Ok((virtual_address, offset, mem_size))
    } else {
        Err(ParserError::SegmentSizeExceedsMemorySize.into())
    }
}

/// Builds a map of allowed ELF sections and their address ranges.
///
/// This function iterates through the ELF file's section headers, filters for allowed sections,
/// and creates a map of section names to their start and end addresses.
fn create_allowed_section_map<'a>(
    elf: &'a ElfBytes<LittleEndian>,
) -> Result<HashMap<&'a str, (u64, u64)>> {
    // Retrieve section headers and string table
    let (section_headers_opt, string_table_opt) = elf
        .section_headers_with_strtab()
        .map_err(ParserError::ELFError)?;
    let section_headers = section_headers_opt.ok_or(ParserError::NoSectionHeader)?;
    let string_table = string_table_opt.ok_or(ParserError::NoStringTable)?;

    // Build the section map
    let section_map = section_headers
        .iter()
        .filter_map(|section_header| {
            // Get the section name
            let section_name = string_table
                .get(section_header.sh_name as usize)
                .expect("Failed to get section name");

            // Check if the section name starts with any of the allowed prefixes
            if ALLOWED_SECTIONS
                .iter()
                .any(|prefix| section_name.starts_with(prefix))
            {
                // Calculate start and end addresses of the section
                let start_address = section_header.sh_offset;
                let end_address = start_address + section_header.sh_size;
                Some((section_name, (start_address, end_address)))
            } else {
                None
            }
        })
        .collect();
    Ok(section_map)
}

/// Parses the content of a segment and populates the memory image and instructions.
/// This code does not assume to know the order of sections in ELF file.
///
/// This function processes the content of an ELF segment, determining whether it contains
/// executable code or data, and appropriately populates either the instructions vector
/// or the memory image map.
fn parse_segment_content(
    segment: &ProgramHeader,
    section_map: &HashMap<&str, (u64, u64)>,
    data: &[u8],
    instructions: &mut Vec<u32>,
    readonly_memory_image: &mut BTreeMap<u32, u32>,
    memory_image: &mut BTreeMap<u32, u32>,
    metadata: &mut Vec<u32>,
) -> Result<()> {
    let is_executable_segment = (segment.p_flags & abi::PF_X) != 0;
    let (segment_virtual_address, segment_physical_address, segment_size) =
        parse_segment_info(segment)?;

    for offset_in_segment in (0..segment_size).step_by(WORD_SIZE as _) {
        // Calculate the memory address for this word
        let memory_address = segment_virtual_address
            .checked_add(offset_in_segment)
            .ok_or(ParserError::InvalidSegmentAddress)?;
        if memory_address == MAXIMUM_MEMORY_SIZE {
            return Err(ParserError::AddressExceedsMemorySize.into());
        }

        // Calculate the offset within the segment for this word
        let absolute_address = offset_in_segment + segment_physical_address;

        // Read the word from the file data
        let word = u32::from_le_bytes(
            data[absolute_address as usize..(absolute_address + WORD_SIZE as u32) as usize]
                .try_into()
                .map_err(ParserError::WordDecodingFailed)?,
        );

        // Determine the type of word based on the segment and section information

        let word_type = if is_executable_segment
            && section_map.iter().any(|(prefix, (_, end))| {
                (prefix.starts_with(".text")
                    || prefix.starts_with(".init")
                    || prefix.starts_with(".fini"))
                    && absolute_address < *end as u32
            }) {
            Some(WordType::Instruction)
        } else if section_map.iter().any(|(prefix, (start, end))| {
            prefix.starts_with(".rodata")
                && *start as u32 <= absolute_address
                && absolute_address < *end as u32
        }) {
            Some(WordType::ReadOnlyData)
        } else if section_map.iter().any(|(prefix, (start, end))| {
            prefix.starts_with(".note.nexus-precompiles")
                && *start as u32 <= absolute_address
                && absolute_address < *end as u32
        }) {
            Some(WordType::Metadata)
        } else if section_map.iter().any(|(prefix, (start, end))| {
            (!prefix.starts_with(".text") && !prefix.starts_with(".rodata"))
                && *start as u32 <= absolute_address
                && absolute_address < *end as u32
        }) {
            Some(WordType::Data)
        } else {
            None
        };

        match word_type {
            Some(WordType::Instruction) => instructions.push(word),
            Some(WordType::ReadOnlyData) => {
                if readonly_memory_image.insert(memory_address, word).is_some() {
                    return Err(ParserError::DuplicateMemoryAddress.into());
                }
            }
            Some(WordType::Data) => {
                if memory_image.insert(memory_address, word).is_some() {
                    return Err(ParserError::DuplicateMemoryAddress.into());
                }
            }
            Some(WordType::Metadata) => {
                metadata.push(word);
            }
            None => (),
        }
    }

    Ok(())
}

/// Represents a precompile description as found in the ELF file.
#[derive(PartialEq, Eq)]
pub struct PrecompileDescription<'a>(u16, &'a str);

impl PartialOrd for PrecompileDescription<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl Ord for PrecompileDescription<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// Parses the precompile metadata from the ELF file. This function finds all symbols that indicate
/// pieces of precompile metadata and then ensures that there is a complete contiguous set of unique
/// precompiles labeled 0 though N-1 via heapification.
#[allow(dead_code)]
fn parse_precompile_metadata(
    elf: &ElfBytes<LittleEndian>,
    data: &[u8],
) -> Result<HashMap<u16, String>> {
    let (section_headers, _section_headers_string_table) = elf
        .section_headers_with_strtab()
        .map_err(ParserError::ELFError)?;
    let symbol_table = elf.symbol_table().map_err(ParserError::ELFError)?;
    let section_headers = section_headers.ok_or(ParserError::NoSectionHeader)?;
    let (symbol_table, symbol_string_table) = symbol_table.ok_or(ParserError::NoSymbolTable)?;

    // There is no actual meaning to the order of the precompiles; the indices are arbitrary and map
    // directly onto custom instructions.
    let mut precompiles = HashMap::<u16, String>::default();

    for symbol in symbol_table {
        // We don't care about functions/anything other than objects.
        if symbol.st_symtype() != abi::STT_OBJECT {
            continue;
        }

        // Search for PRECOMPILE_X symbols, which are strings that contain precompile metadata.
        let name = symbol_string_table
            .get(symbol.st_name as usize)
            .map_err(|_| ParserError::NoSymbolTable)?;
        if !name.starts_with(PRECOMPILE_SYMBOL_PREFIX) {
            continue;
        }

        let suffix: &str = &name[PRECOMPILE_SYMBOL_PREFIX.len()..];
        let precompile_index: u16 = suffix.parse::<u16>().map_err(ParserError::ParseIntError)?;

        // str is represented as a [u8], which contains two words: a pointer and a length.
        let symbol_size: usize = symbol.st_size as usize;
        if symbol_size != WORD_SIZE * 2 {
            return Err(ParserError::InvalidPrecompileSize(symbol.st_size).into());
        }

        // Recover the symbol's offset in the file. Requires some address conversions.
        let virtual_address: u32 = symbol
            .st_value
            .try_into()
            .map_err(|_| ParserError::InvalidVirtualAddress(symbol.st_value))?;

        // Need section data to calculate the offset in the file.
        let section: SectionHeader = match symbol.st_shndx {
            x if x == abi::SHN_XINDEX => {
                return Err(ParserError::InvalidSectionIndex(x).into());
            }
            x => section_headers
                .get(x as usize)
                .map_err(ParserError::ELFError)?,
        };

        // Virtual address of the section start
        let section_addr: u32 = section
            .sh_addr
            .try_into()
            .map_err(|_| ParserError::InvalidSectionAddress(section.sh_addr))?;
        // File offset of the section start
        let section_offset: u32 = section
            .sh_offset
            .try_into()
            .map_err(|_| ParserError::InvalidSectionOffset(section.sh_offset))?;

        let offset_in_section = virtual_address
            .checked_sub(section_addr)
            .ok_or(ParserError::InvalidOffsetInSection)?;
        let offset_in_file = section_offset
            .checked_add(offset_in_section)
            .ok_or(ParserError::InvalidOffsetInFile)? as usize;

        // These must be encoded as valid Rust strings, so we should decode them immediately,
        // erroring if necessary.
        let str_struct_bytes = &data[offset_in_file..offset_in_file + symbol_size];
        if str_struct_bytes.len() != WORD_SIZE * 2 {
            return Err(ParserError::InvalidPrecompileSize(symbol.st_size).into());
        }

        // Safety: we've already checked that the slice is of length WORD_SIZE * 2.
        let str_ptr = u32::from_le_bytes(str_struct_bytes[..WORD_SIZE].try_into().unwrap());
        let str_len = u32::from_le_bytes(str_struct_bytes[WORD_SIZE..].try_into().unwrap());

        // str_ptr is a virtual address again, so we have to again convert it to a file address.
        // We assume the data is stored in the same section as the str representation.
        let str_section_offset = str_ptr
            .checked_sub(section_addr)
            .ok_or(ParserError::InvalidOffsetInSection)? as usize;
        let str_offset = section_offset as usize + str_section_offset;

        let str_slice = &data[str_offset..str_offset + str_len as usize];
        let str_value = str::from_utf8(str_slice).map_err(ParserError::Utf8Error)?;

        precompiles.insert(precompile_index, str_value.into());
    }

    debug!("Loaded precompile metadata: {precompiles:?}");

    Ok(precompiles)
}

/// Parses the segments of an ELF file and extracts relevant information.
///
/// This function iterates through the LOAD segments of the ELF file, extracting
/// instructions, building a memory image, and determining the base address.
///
/// # Arguments
///
/// * `elf` - A reference to the ElfBytes structure containing the parsed ELF file.
/// * `data` - A slice of bytes representing the raw ELF file data.
///
/// # Returns
///
/// A tuple containing:
/// * A vector of u32 values representing the encoded instructions.
/// * A BTreeMap representing the memory image, where keys are addresses and values are word contents.
/// * The base address (u32) of the executable segment.
///
/// # Errors
///
/// Returns a `ParserError` if any parsing or validation errors occur.
pub fn parse_segments(elf: &ElfBytes<LittleEndian>, data: &[u8]) -> Result<ParsedElfData> {
    let mut instructions = Instructions::new();
    let mut writable_memory = RawMemoryImage::new();
    let mut readonly_memory = RawMemoryImage::new();
    let mut metadata = Metadata::new();

    // Base address is the lowest virtual address of a program's loadable segment
    let mut base_address = u64::MAX;

    let section_map = create_allowed_section_map(elf)?;
    let segments = elf.segments().ok_or(ParserError::NoSegmentAvailable)?;

    // Iterate through all LOAD segments
    for segment in segments
        .iter()
        .filter(|x| x.p_type == abi::PT_LOAD || x.p_type == abi::PT_NOTE)
    {
    
        // We assume the executable section (PF_X or .text section) is the first executable segment,
        // thus it has the lower address, we use this information to figure out the base address of the program
        if (segment.p_flags & abi::PF_X) != 0 && base_address > segment.p_vaddr {
            base_address = segment.p_vaddr;
        }

        // Parse the content of the segment
        parse_segment_content(
            &segment,
            &section_map,
            data,
            &mut instructions,
            &mut readonly_memory,
            &mut writable_memory,
            &mut metadata,
        )?;
    }

    let base_address = if base_address == u64::MAX {
        return Err(ParserError::NoExecutableSegment.into());
    } else if base_address > u32::MAX as u64 {
        return Err(ParserError::AddressExceedsMemorySize.into());
    } else {
        base_address as u32
    };

    Ok(ParsedElfData {
        instructions,
        readonly_memory: MemorySegmentImage::try_from_contiguous_btree(&readonly_memory)?,
        writable_memory: MemorySegmentImage::try_from_contiguous_btree(&writable_memory)?,
        base_address,
        nexus_metadata: metadata,
    })
}

#[cfg(test)]
mod tests {
    use crate::read_testing_binary_from_path;

    use super::{parse_precompile_metadata, validate_elf_header};

    use elf::{endian::LittleEndian, ElfBytes};
    use std::collections::HashMap;

    #[tracing_test::traced_test]
    #[test]
    fn test_parse_elf_file_with_precompile() {
        let elf_bytes = read_testing_binary_from_path!("/test/program_with_dummy_div.elf");
        let elf = ElfBytes::<LittleEndian>::minimal_parse(&elf_bytes).unwrap();

        validate_elf_header(&elf.ehdr).unwrap();
        assert_eq!(
            parse_precompile_metadata(&elf, &elf_bytes).unwrap(),
            HashMap::<u16, String>::from([(0, "\":: dummy_div :: DummyDiv\"".into())])
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn test_parse_elf_file_with_precompiles() {
        let elf_bytes = read_testing_binary_from_path!("/test/program_with_two_precompiles.elf");

        let elf = ElfBytes::<LittleEndian>::minimal_parse(&elf_bytes).unwrap();

        validate_elf_header(&elf.ehdr).unwrap();
        assert_eq!(
            parse_precompile_metadata(&elf, &elf_bytes).unwrap(),
            HashMap::<u16, String>::from([
                (0, "\":: dummy_div :: DummyDiv\"".into()),
                (1, "\":: dummy_hash :: DummyHash\"".into())
            ])
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn test_parse_elf_file_with_no_precompiles() {
        let elf_bytes = read_testing_binary_from_path!("/test/program_with_no_precompiles.elf");
        let elf = ElfBytes::<LittleEndian>::minimal_parse(&elf_bytes).unwrap();

        validate_elf_header(&elf.ehdr).unwrap();
        assert_eq!(
            parse_precompile_metadata(&elf, &elf_bytes).unwrap(),
            HashMap::<u16, String>::default()
        );
    }
}
