use crate::elf::ElfFile;
use crate::riscv::{decode_instruction, BasicBlock};

pub use super::executor::Emulator;
pub use super::layout::LinearMemoryLayout;
use super::registry;

use nexus_common::constants::WORD_SIZE;
use nexus_common::memory::MemoryRecords;
use nexus_common::riscv::{opcode::BuiltinOpcode, Opcode};
use std::collections::BTreeMap;

pub type MemoryTranscript = Vec<MemoryRecords>;

pub trait IOEntry {
    fn new(address: u32, value: u8) -> Self;

    fn new_from_offset(base: u32, offset: u32, value: u8) -> Self;

    fn address(&self) -> u32;

    fn value(&self) -> u8;
}

macro_rules! io {
    ( $id:ident ) => {
        impl IOEntry for $id {
            fn new(address: u32, value: u8) -> Self {
                Self { address, value }
            }

            fn new_from_offset(base: u32, offset: u32, value: u8) -> Self {
                Self {
                    address: base + offset,
                    value,
                }
            }

            fn address(&self) -> u32 {
                self.address
            }

            fn value(&self) -> u8 {
                self.value
            }
        }
    };
}

/// Convert `rin` and `wou` instructions into `lb` and `sb` for the second pass in two pass tracing.
pub fn convert_instruction(registry: &registry::InstructionExecutorRegistry, instr: &u32) -> u32 {
    let mut decoded_ins = decode_instruction(*instr);

    if registry.is_read_input(&decoded_ins.opcode) {
        decoded_ins.opcode = Opcode::from(BuiltinOpcode::LW);
        decoded_ins.encode()
    } else if registry.is_write_output(&decoded_ins.opcode) {
        decoded_ins.opcode = Opcode::from(BuiltinOpcode::SW);
        decoded_ins.encode()
    } else {
        *instr
    }
}

pub fn io_entries_into_vec<T: IOEntry>(base: u32, entries: &[T]) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    vec.resize(entries.len(), u8::default());

    entries.iter().for_each(|entry: &T| {
        let loc = (entry.address() - base) as usize;
        vec[loc] = entry.value();
    });

    vec
}

pub fn map_into_io_entries<T: IOEntry>(map: &BTreeMap<u32, u32>) -> Vec<T> {
    map.iter()
        .flat_map(|(addr, val)| {
            val.to_le_bytes()
                .iter()
                .enumerate()
                .map(|(idx, byte)| T::new(addr + idx as u32, *byte))
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn slice_into_io_entries<T: IOEntry>(base: u32, values: &[u8]) -> Vec<T> {
    values
        .iter()
        .enumerate()
        .map(|(idx, val)| T::new_from_offset(base, idx as u32, *val))
        .collect()
}

pub fn elf_into_program_info(elf: &ElfFile, layout: &LinearMemoryLayout) -> ProgramInfo {
    ProgramInfo {
        initial_pc: layout.program_start(),
        program: elf
            .instructions
            .iter()
            .enumerate()
            .map(|(pc_offset, instruction)| ProgramMemoryEntry {
                pc: layout.program_start() + (pc_offset * WORD_SIZE) as u32,
                instruction_word: *instruction,
            })
            .collect(),
    }
}

// One entry per byte because RO memory can be accessed bytewise
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MemoryInitializationEntry {
    pub address: u32,
    pub value: u8,
}

// One entry per byte because WO memory can be accessed bytewise
#[derive(Debug, Copy, Clone)]
pub struct PublicOutputEntry {
    pub address: u32,
    pub value: u8,
}

io!(MemoryInitializationEntry);
io!(PublicOutputEntry);

// One entry per instruction because program memory is always accessed instruction-wise
#[derive(Debug, Copy, Clone)]
pub struct ProgramMemoryEntry {
    pub pc: u32,
    pub instruction_word: u32,
}

#[derive(Debug, Clone)]
pub struct ProgramInfo {
    // The program counter where the execution starts
    pub initial_pc: u32,
    pub program: Vec<ProgramMemoryEntry>,
}

impl ProgramInfo {
    pub fn dummy() -> Self {
        Self {
            initial_pc: 0,
            program: vec![],
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct BasicBlockEntry {
    pub start: u32,
    pub end: u32,
    pub block: BasicBlock,
}

impl BasicBlockEntry {
    pub fn new(start: u32, block: BasicBlock) -> Self {
        BasicBlockEntry {
            start,
            end: start + (block.len() * WORD_SIZE) as u32,
            block,
        }
    }
}

pub trait InternalView {
    /// Return components of the program memory.
    fn get_program_memory(&self) -> &ProgramInfo;

    /// Return information about the public input, static ROM, and static RAM.
    fn get_initial_memory(&self) -> &[MemoryInitializationEntry];

    /// Return information about the public input.
    fn get_public_output(&self) -> &[PublicOutputEntry];

    /// Return information about the exit code.
    fn get_exit_code(&self) -> &[PublicOutputEntry];

    /// Add debug logs from another emulator.
    fn add_logs(&mut self, emulator: &impl Emulator);
}

#[derive(Debug, Clone)]
pub struct View {
    pub(crate) memory_layout: Option<LinearMemoryLayout>,
    pub(crate) debug_logs: Vec<Vec<u8>>,
    pub(crate) program_memory: ProgramInfo,
    // When not available, initial_memory can be None
    pub(crate) initial_memory: Option<Vec<MemoryInitializationEntry>>,
    /// The number of all addresses under RAM memory checking
    pub(crate) tracked_ram_size: usize,
    pub(crate) exit_code: Vec<PublicOutputEntry>,
    pub(crate) output_memory: Vec<PublicOutputEntry>,
    pub(crate) associated_data: Vec<u8>,
}

impl View {
    /// Construct a view out of its raw parts.
    #[allow(clippy::too_many_arguments)] // extra thought needed what's the best approach to reduce args
    pub fn new(
        memory_layout: &Option<LinearMemoryLayout>,
        debug_logs: &Vec<Vec<u8>>,
        program_memory: &ProgramInfo,
        initial_memory: &Vec<MemoryInitializationEntry>,
        tracked_ram_size: usize,
        exit_code: &Vec<PublicOutputEntry>,
        output_memory: &Vec<PublicOutputEntry>,
        associated_data: &Vec<u8>,
    ) -> Self {
        Self {
            memory_layout: memory_layout.to_owned(),
            debug_logs: debug_logs.to_owned(),
            program_memory: program_memory.to_owned(),
            initial_memory: Some(initial_memory.to_owned()),
            tracked_ram_size,
            exit_code: exit_code.to_owned(),
            output_memory: output_memory.to_owned(),
            associated_data: associated_data.to_owned(),
        }
    }

    /// Return the raw bytes of the public input, if any.
    pub fn view_public_input(&self) -> Option<Vec<u8>> {
        self.memory_layout.map(|layout| {
            let initial_memory = self
                .initial_memory
                .as_ref()
                .expect("initial memory should be available");
            io_entries_into_vec(
                layout.public_input_start() + WORD_SIZE as u32,
                initial_memory
                    .iter()
                    .filter(|entry: &&MemoryInitializationEntry| {
                        layout.public_input_start() + WORD_SIZE as u32 <= entry.address
                            && entry.address < layout.public_input_end()
                    })
                    .copied()
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
        })
    }

    /// Return the raw bytes of the exit code, if any.
    pub fn view_exit_code(&self) -> Option<Vec<u8>> {
        self.memory_layout
            .map(|layout| io_entries_into_vec(layout.exit_code(), &self.exit_code))
    }

    /// Return the raw bytes of the public output, if any.
    pub fn view_public_output(&self) -> Option<Vec<u8>> {
        self.memory_layout
            .map(|layout| io_entries_into_vec(layout.public_output_start(), &self.output_memory))
    }

    /// Return the number of all addresses under RAM memory checking.
    pub fn view_tracked_ram_size(&self) -> usize {
        self.tracked_ram_size
    }

    /// Return the raw bytes of the associated data, if any.
    pub fn view_associated_data(&self) -> Option<Vec<u8>> {
        if self.memory_layout.is_some() {
            Some(self.associated_data.clone())
        } else {
            None
        }
    }

    /// Retrieve the raw debug logs, if any.
    pub fn view_debug_logs(&self) -> Option<Vec<Vec<u8>>> {
        Some(self.debug_logs.clone())
    }
}

impl InternalView for View {
    /// Return infomation about the program memory.
    fn get_program_memory(&self) -> &ProgramInfo {
        &self.program_memory
    }

    /// Return information about the public input, static ROM, and static RAM.
    fn get_initial_memory(&self) -> &[MemoryInitializationEntry] {
        let initial_memory = self
            .initial_memory
            .as_ref()
            .expect("initial memory should be available");
        initial_memory
    }

    /// Return information about the public input.
    fn get_public_output(&self) -> &[PublicOutputEntry] {
        &self.output_memory
    }

    /// Return information about the exit code.
    fn get_exit_code(&self) -> &[PublicOutputEntry] {
        &self.exit_code
    }

    /// Add logs from another emulator.
    fn add_logs(&mut self, emulator: &impl Emulator) {
        if let Some(logs) = &emulator.get_executor().logs {
            self.debug_logs = logs.to_vec();
        }
    }
}
