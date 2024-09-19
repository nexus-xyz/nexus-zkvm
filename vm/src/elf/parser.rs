//! ELF File Parser for RISC-V 32-bit Executables
//!
//! This module provides functionality to parse and validate ELF (Executable and Linkable Format)
//! files specifically for RISC-V 32-bit architecture. It's designed to work with the `elf` crate
//! and uses custom error types defined in the `error` module.
//!
//! Key Features:
//! - Validates ELF headers for RISC-V 32-bit executables
//! - Parses segment information and extracts executable content
//! - Supports Harvard architecture with separate instruction and data memories
//! - Handles allowed sections: .text, .data, .sdata, and .rodata
//!
//! Main Components:
//! - `validate_elf_header`: Ensures the ELF file meets RISC-V 32-bit executable requirements
//! - `parse_segments`: Extracts instructions and builds memory images from ELF segments
//! - `create_allowed_section_map`: Builds a map of allowed ELF sections and their address ranges
//! - `parse_segment_content`: Processes segment content and populates instruction and memory structures
//!
//! The parser distinguishes between different types of memory:
//! - Instruction memory (read-only)
//! - Read-only data memory
//! - Writable data memory
//!
//! Note: This parser assumes a little-endian RISC-V architecture and is specifically designed for 32-bit executables.
//! It does not make assumptions about the order of sections in the ELF file.

use elf::{
    abi,
    endian::LittleEndian,
    file::{Class, FileHeader},
    segment::ProgramHeader,
    ElfBytes,
};
use std::collections::{BTreeMap, HashMap};

use super::error::{ParserError, Result};

type Instructions = Vec<u32>;
type MemoryImage = BTreeMap<u32, u32>;

pub struct ParsedElfData {
    pub instructions: Instructions,
    pub readonly_memory: MemoryImage,
    pub writable_memory: MemoryImage,
    pub base_address: u64,
}

/// The maximum size of the memory in bytes.
const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// The size of a word in bytes.
pub const WORD_SIZE: u32 = 4;

/// Defines the allowed sections for Harvard architecture:
/// - Instruction memory: .text
/// - Data memory: .data, .sdata, .rodata
///
/// When building the section map, only these sections and their variants are considered.
/// Section names starting with any of these prefixes are included (e.g., .text1, .data2).
/// All other sections are ignored during parsing.
const ALLOWED_SECTIONS: [&str; 6] = [".text", ".data", ".sdata", ".rodata", ".init", ".fini"];

enum WordType {
    Instruction,
    ReadOnlyData,
    Data,
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
        return Err(ParserError::Not32Bit);
    }

    if header.e_machine != abi::EM_RISCV {
        return Err(ParserError::NotRiscV);
    }

    if header.e_type != abi::ET_EXEC {
        return Err(ParserError::NotExecutable);
    }

    if header.e_phnum == 0 {
        return Err(ParserError::NoProgramHeader);
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
        .map_err(|_| ParserError::InvalidVirtualAddress)?;

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
    if virtual_address % WORD_SIZE != 0 {
        return Err(ParserError::UnalignedVirtualAddress);
    }

    // Ensure the 0 < file_size <= mem_size and the total size does not exceed the maximum memory size
    if (0 < file_size) && (file_size <= mem_size) && (file_size + offset < MAXIMUM_MEMORY_SIZE) {
        Ok((virtual_address, offset, mem_size))
    } else {
        Err(ParserError::SegmentSizeExceedsMemorySize)
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
) -> Result<()> {
    let is_executable_segment = (segment.p_flags & abi::PF_X) != 0;
    let is_data_segment = (segment.p_flags & abi::PF_W) != 0;

    let (virtual_address, offset, file_size) = parse_segment_info(segment)?;

    for address in (0..file_size).step_by(WORD_SIZE as _) {
        // Calculate the memory address for this word
        let memory_address = virtual_address
            .checked_add(address)
            .ok_or(ParserError::InvalidSegmentAddress)?;
        if memory_address == MAXIMUM_MEMORY_SIZE {
            return Err(ParserError::AddressExceedsMemorySize);
        }

        // Calculate the offset within the segment for this word
        let segment_offset = address + offset;

        // Read the word from the file data
        let word = u32::from_le_bytes(
            data[segment_offset as usize..(segment_offset + WORD_SIZE) as usize]
                .try_into()
                .unwrap(),
        );

        // Determine the type of word based on the segment and section information
        let word_type = if is_executable_segment
            && section_map.iter().any(|(prefix, (_, end))| {
                prefix.starts_with(".text") && segment_offset < *end as u32
            }) {
            Some(WordType::Instruction)
        } else if section_map.iter().any(|(prefix, (start, end))| {
            prefix.starts_with(".rodata")
                && *start as u32 <= segment_offset
                && segment_offset < *end as u32
        }) {
            Some(WordType::ReadOnlyData)
        } else if is_data_segment
            && section_map.iter().any(|(prefix, (start, end))| {
                (!prefix.starts_with(".text") && !prefix.starts_with(".rodata"))
                    && *start as u32 <= segment_offset
                    && segment_offset < *end as u32
            })
        {
            Some(WordType::Data)
        } else {
            None
        };

        match word_type {
            Some(WordType::Instruction) => instructions.push(word),
            Some(WordType::ReadOnlyData) => {
                if readonly_memory_image.insert(memory_address, word).is_some() {
                    return Err(ParserError::DuplicateMemoryAddress);
                }
            }
            Some(WordType::Data) => {
                if memory_image.insert(memory_address, word).is_some() {
                    return Err(ParserError::DuplicateMemoryAddress);
                }
            }
            None => (),
        }
    }

    Ok(())
}

#[allow(dead_code)]
fn debug_segment_info(segment: &ProgramHeader, section_map: &HashMap<&str, (u64, u64)>) {
    println!("Program Header Information:");
    println!("  Segment Type: 0x{:08x}", segment.p_type);
    println!("  File Offset: 0x{:016x}", segment.p_offset);
    println!("  Virtual Address: 0x{:016x}", segment.p_vaddr);
    println!("  Physical Address: 0x{:016x}", segment.p_paddr);
    println!("  File Size: {} bytes", segment.p_filesz);
    println!("  Memory Size: {} bytes", segment.p_memsz);
    println!("  Flags: 0x{:08x}", segment.p_flags);
    println!("  Alignment: 0x{:016x}", segment.p_align);
    for (key, (start, end)) in section_map {
        println!("Section {}: {} -> {}", key, start, end);
    }
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
    let mut writable_memory = MemoryImage::new();
    let mut readonly_memory = MemoryImage::new();

    // Base address is the lowest virtual address of a program's loadable segment
    let mut base_address = u64::MAX;

    let section_map = create_allowed_section_map(elf)?;

    // Iterate through all LOAD segments
    for segment in elf
        .segments()
        .ok_or(ParserError::NoSegmentAvailable)?
        .iter()
        .filter(|x| x.p_type == abi::PT_LOAD)
    {
        #[cfg(debug_assertions)]
        debug_segment_info(&segment, &section_map);
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
        )?;
    }

    Ok(ParsedElfData {
        instructions,
        readonly_memory,
        writable_memory,
        base_address,
    })
}
