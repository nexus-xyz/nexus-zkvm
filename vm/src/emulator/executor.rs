//! # RISC-V Emulator Executor
//!
//! This module contains the core execution logic for the RISC-V emulator.
//! It defines the `Executor` struct, `HarvardEmulator`, and `LinearEmulator` structs
//! along with their associated methods for executing RISC-V instructions and managing
//! the emulator's state.
//!
//! ## Key Components
//!
//! - `Executor`: The core struct containing CPU state, instruction registry, and other execution-related data.
//! - `HarvardEmulator`: An emulator implementation using Harvard architecture (separate instruction and data memory).
//! - `LinearEmulator`: An emulator implementation using Linear architecture (unified memory from Harvard architecture
//!    with a single memory space, with added read and write protection).
//! - `Emulator` trait: Defines common methods for both emulator types.
//! - `View`: A struct representing the final state of the emulator after execution.
//!
//! ## Main Features
//!
//! - Instruction execution for both Harvard and Linear architectures.
//! - Basic block fetching and caching for improved performance.
//! - Support for system calls and custom instructions.
//! - Memory management for different memory types (RO, WO, RW, NA).
//! - Cycle counting and profiling capabilities.
//! - Support for public and private inputs.
//! - Debug logging functionality.
//! - Associated data handling in LinearEmulator.
//! - Precompile metadata support.
//!
//! ## Basic Block Execution
//!
//! Both emulator types use a basic block approach for efficiency:
//! 1. Fetch or decode a basic block starting from the current PC.
//! 2. Execute all instructions in the block sequentially.
//! 3. Update the PC and continue with the next block.
//!
//! ## Memory Layout
//!
//! The `LinearEmulator` uses a `LinearMemoryLayout` to manage different memory regions:
//! - Program memory
//! - Public input
//! - Associated data (AD)
//! - Exit code
//! - Public output
//! - Heap
//! - Stack
//!
//! ## Error Handling
//!
//! The emulator uses a `Result` type for error handling, with custom error types
//! defined in the `error` module.
//!
//! ## Examples
//!
//! ### Creating and Running a Harvard Emulator
//!
//! ```rust
//! use nexus_vm::elf::ElfFile;
//! use nexus_vm::emulator::{Emulator, HarvardEmulator};
//!
//! let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
//! let mut emulator = HarvardEmulator::from_elf(&elf_file, &[], &[]);
//!
//! match emulator.execute(false) {
//!     Ok(_) => println!("Program executed successfully"),
//!     Err(e) => println!("Execution error: {:?}", e),
//! }
//! ```
//!
//! ### Creating and Running a Linear Emulator
//!
//! ```rust
//! use nexus_vm::elf::ElfFile;
//! use nexus_vm::emulator::{Emulator, LinearEmulator, LinearMemoryLayout};
//!
//! let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
//! let mut emulator = LinearEmulator::from_elf(LinearMemoryLayout::default(), &[], &elf_file, &[], &[]);
//!
//! match emulator.execute(false) {
//!     Ok(_) => println!("Program executed successfully"),
//!     Err(e) => println!("Execution error: {:?}", e),
//! }
//! ```
//!
//! ### Creating a Linear Emulator from an ELF file
//!
//! ```rust
//! use nexus_vm::elf::ElfFile;
//! use nexus_vm::emulator::{LinearEmulator, LinearMemoryLayout};
//! use nexus_vm::emulator::Emulator;
//! use nexus_vm::error::VMError;
//!
//! let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
//! let memory_layout = LinearMemoryLayout::default();
//!
//! let mut linear_emulator = LinearEmulator::from_elf(
//!     memory_layout,
//!     &[],
//!     &elf_file,
//!     &[],
//!     &[]
//! );
//!
//! assert_eq!(linear_emulator.execute(true), Err(VMError::VMExited(0)));
//! ```
//!
//! ### Creating a Linear Emulator from a Harvard Emulator
//!
//! ```no_run
//! use nexus_vm::elf::ElfFile;
//! use nexus_vm::emulator::{HarvardEmulator, LinearEmulator};
//! use nexus_vm::emulator::Emulator;
//! use nexus_vm::error::VMError;
//!
//! let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
//! let harvard_emulator = HarvardEmulator::from_elf(&elf_file, &[], &[]);
//!
//! let associated_data = vec![0u8; 100];
//! let private_input = vec![0u8; 100];
//!
//! let mut linear_emulator = LinearEmulator::from_harvard(
//!     &harvard_emulator,
//!     elf_file,
//!     &associated_data,
//!     &private_input
//! ).expect("Failed to create Linear Emulator from Harvard Emulator");
//!
//! assert_eq!(linear_emulator.execute(true), Err(VMError::VMExited(0)));
//! ```
//!
//! This module provides a flexible and efficient implementation of RISC-V emulation,
//! supporting both Harvard and Linear architectures, and offering features like
//! basic block caching, custom instruction support, debug logging, and associated data handling.

use super::{
    layout::LinearMemoryLayout, memory_stats::*, registry::InstructionExecutorRegistry, *,
};
use crate::{
    cpu::{instructions::InstructionResult, Cpu},
    elf::ElfFile,
    error::{Result, VMError},
    memory::{
        FixedMemory, LoadOp, MemoryProcessor, MemoryRecords, Modes, StoreOp, UnifiedMemory,
        VariableMemory, NA, RO, RW, WO,
    },
    riscv::{decode_until_end_of_a_block, BasicBlock, Instruction, Opcode, Register},
    system::SyscallInstruction,
};

use nexus_common::{
    constants::{ELF_TEXT_START, MEMORY_TOP, WORD_SIZE},
    cpu::{InstructionExecutor, Registers},
    memory::MemAccessSize,
    word_align,
};
use rangemap::RangeMap;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
};

#[derive(Debug, Default)]
pub struct Executor {
    // The CPU
    pub cpu: Cpu,

    // Instruction Executor
    pub instruction_executor: InstructionExecutorRegistry,

    // The private input tape as a FIFO queue.
    pub private_input_tape: VecDeque<u8>,

    // The global clock counter
    pub global_clock: usize,

    // Reference component of basic block cache to improve performance
    basic_block_ref_cache: RangeMap<u32, u32>,

    // Basic block cache to improve performance
    basic_block_cache: BTreeMap<u32, BasicBlockEntry>,

    // The base address of the program
    #[allow(unused)]
    base_address: u32,

    // The entrypoint of the program
    entrypoint: u32,

    // The cycles tracker: (name, (cycle_count, occurrence))
    pub cycle_tracker: HashMap<String, (usize, usize)>,

    // Debug logs written by the guest program
    pub logs: Option<Vec<Vec<u8>>>,

    // A map of memory addresses to the last timestamp when they were accessed
    pub access_timestamps: HashMap<u32, usize>,
}

impl Executor {
    /// Adds a new opcode and its corresponding execution function to the emulator.
    fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<()> {
        self.instruction_executor.add_opcode::<IE>(op)
    }

    /// Set or overwrite private input into the private input tape
    fn set_private_input(&mut self, private_input: &[u8]) {
        self.private_input_tape = VecDeque::<u8>::from(private_input.to_vec());
    }

    /// Set whether to capture logs or print out.
    pub(crate) fn capture_logs(&mut self, capture: bool) {
        if capture && self.logs.is_none() {
            self.logs = Some(Vec::new());
        }

        if !capture && self.logs.is_some() {
            self.logs = None;
        }
    }
}

pub trait Emulator {
    /// Execute a system call instruction
    ///
    /// 1. Decode the system call parameters from register a0-a6
    /// 2. Read necessary data from memory
    /// 3. Execute the system call, modify the emulator if necessary
    /// 4. Write results back to memory
    /// 5. Update CPU state, the return result is stored in register a0
    #[allow(clippy::type_complexity)]
    fn execute_syscall(
        executor: &mut Executor,
        memory: &mut impl MemoryProcessor,
        memory_layout: Option<LinearMemoryLayout>,
        bare_instruction: &Instruction,
        force_provable_transcript: bool,
    ) -> Result<(InstructionResult, (HashSet<LoadOp>, HashSet<StoreOp>))> {
        let mut syscall_instruction = SyscallInstruction::decode(bare_instruction, &executor.cpu)?;
        let load_ops = syscall_instruction.memory_read(memory)?;
        syscall_instruction.execute(executor, memory, memory_layout, force_provable_transcript)?;
        let result = syscall_instruction.get_result().map(|(_, value)| value);
        let store_ops = syscall_instruction.memory_write(memory)?;
        syscall_instruction.write_back(&mut executor.cpu);

        // Safety: during the first pass, the Write and CycleCount syscalls can read from memory
        //         however, during the second pass these are no-ops, so we never need a record
        Ok((result, (load_ops, store_ops)))
    }

    /// Executes a single RISC-V instruction.
    ///
    /// 1. Retrieves the instruction executor function for the given opcode via HashMap.
    /// 2. Executes the instruction using the appropriate executor function.
    /// 3. Updates the program counter (PC) if the instruction is not a branch or jump.
    /// 4. Increments the global clock.
    fn execute_instruction(
        &mut self,
        bare_instruction: &Instruction,
        force_provable_transcript: bool,
    ) -> Result<(InstructionResult, MemoryRecords)>;

    /// Fetches or decodes a basic block starting from the current PC.
    ///
    /// This function performs the following steps:
    /// 1. Checks if a basic block containing the current PC is already in the cache.
    /// 2. If cached, returns the existing block.
    /// 3. If not cached, decodes a new block, caches it, and returns it.
    ///
    /// # Returns
    /// if success, return a `BasicBlockEntry` starting at the current PC.
    fn fetch_block(&mut self, pc: u32) -> Result<BasicBlockEntry>;

    /// Return a reference to the internal executor component used by the emulator.
    fn get_executor(&self) -> &Executor;

    /// Return a mutable reference to the internal executor component used by the emulator.
    fn get_executor_mut(&mut self) -> &mut Executor;

    /// Execute an entire basic block.
    fn execute_basic_block(
        &mut self,
        basic_block_entry: &BasicBlockEntry,
        force_provable_transcript: bool,
    ) -> Result<(Vec<InstructionResult>, MemoryTranscript)> {
        #[cfg(debug_assertions)]
        basic_block_entry
            .block
            .print_with_offset(self.get_executor().cpu.pc.value as usize);

        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        let at = (self.get_executor().cpu.pc.value as usize - basic_block_entry.start as usize)
            / WORD_SIZE;

        // Execute the instructions in the basic block
        for instruction in basic_block_entry.block.0[at..].iter() {
            let (res, mem) = self.execute_instruction(instruction, force_provable_transcript)?;
            results.push(res);
            transcript.push(mem);
        }

        Ok((results, transcript))
    }

    /// Execute an entire program.
    fn execute(
        &mut self,
        force_provable_transcript: bool,
    ) -> Result<(Vec<InstructionResult>, MemoryTranscript)> {
        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        loop {
            let basic_block_entry = self.fetch_block(self.get_executor().cpu.pc.value)?;
            let (res, mem) =
                self.execute_basic_block(&basic_block_entry, force_provable_transcript)?;

            results.extend(res);
            transcript.extend(mem);
        }
    }

    /// Adds a new opcode and its corresponding execution function to the emulator.
    fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<()> {
        self.get_executor_mut().add_opcode::<IE>(op)
    }

    /// Set or overwrite private input into the private input tape
    fn set_private_input(&mut self, private_input: &[u8]) {
        self.get_executor_mut().set_private_input(private_input)
    }

    /// Update and return previous timestamps, but it currently works word-wise, so not used.
    #[allow(dead_code)]
    fn manage_timestamps(&mut self, size: &MemAccessSize, address: &u32) -> usize {
        let half_aligned_address = address & !(WORD_SIZE / 2 - 1) as u32;
        let full_aligned_address = address & !(WORD_SIZE - 1) as u32;

        let prev = match size {
            MemAccessSize::Byte => max(
                *self
                    .get_executor()
                    .access_timestamps
                    .get(address)
                    .unwrap_or(&0),
                max(
                    *self
                        .get_executor()
                        .access_timestamps
                        .get(&half_aligned_address)
                        .unwrap_or(&0),
                    *self
                        .get_executor()
                        .access_timestamps
                        .get(&full_aligned_address)
                        .unwrap_or(&0),
                ),
            ),
            MemAccessSize::HalfWord => max(
                *self
                    .get_executor()
                    .access_timestamps
                    .get(address)
                    .unwrap_or(&0),
                *self
                    .get_executor()
                    .access_timestamps
                    .get(&full_aligned_address)
                    .unwrap_or(&0),
            ),
            MemAccessSize::Word => *self
                .get_executor()
                .access_timestamps
                .get(address)
                .unwrap_or(&0),
        };

        let clk = self.get_executor().global_clock;
        self.get_executor_mut()
            .access_timestamps
            .insert(*address, clk);
        prev
    }

    /// Return a `View` capturing the end-state of the emulator.
    fn finalize(&self) -> View;
}

#[derive(Debug)]
pub struct HarvardEmulator {
    // The core execution components
    pub executor: Executor,

    // The instruction memory image
    instruction_memory: FixedMemory<RO>,

    // The input memory image
    input_memory: FixedMemory<RO>,

    // The output memory image
    output_memory: VariableMemory<WO>,

    // Content of static rom image
    static_rom_image: BTreeMap<u32, u8>,

    // Initial content of static ram image
    static_ram_image: BTreeMap<u32, u8>,

    // A combined read-only (in part) and read-write (in part) memory image
    pub data_memory: UnifiedMemory,

    // Tracker for the memory sizes since they are not known ahead of time
    memory_stats: MemoryStats,
}

impl Default for HarvardEmulator {
    fn default() -> Self {
        // a suitable default for testing
        Self {
            executor: Executor::default(),
            instruction_memory: FixedMemory::<RO>::new(0, 0x1000),
            input_memory: FixedMemory::<RO>::new(0, 0x1000),
            output_memory: VariableMemory::<WO>::default(),
            static_rom_image: BTreeMap::new(),
            static_ram_image: BTreeMap::new(),
            data_memory: UnifiedMemory::default(),
            memory_stats: MemoryStats::default(),
        }
    }
}

impl HarvardEmulator {
    pub fn from_elf(elf: &ElfFile, public_input: &[u8], private_input: &[u8]) -> Self {
        // the stack and heap will also be stored in this variable memory segment
        let text_end = (elf.instructions.len() * WORD_SIZE) as u32 + elf.base;
        let mut data_end = *elf.ram_image.last_key_value().unwrap_or((&text_end, &0)).0;
        let mut data_memory =
            UnifiedMemory::from(VariableMemory::<RW>::from(elf.ram_image.clone()));

        let ro_data_base_address: u32 = *elf.rom_image.first_key_value().unwrap_or((&0, &0)).0;
        let ro_data_end = *elf.rom_image.keys().max().unwrap_or(&0);
        if !elf.rom_image.is_empty() {
            let mut ro_data: Vec<u32> =
                vec![0; ro_data_end as usize + 1 - ro_data_base_address as usize];

            for (addr, &value) in &elf.rom_image {
                ro_data[(addr - ro_data_base_address) as usize] = value;
            }

            // Linker places data after rodata, but need to guard against edge case of empty data.
            // We also advance the `data_end` past the end of the last address in the data segment
            // because that address is used to set the base address of the heap, which needs to be
            // aligned to `WORD_SIZE` and not overlap the final word of the data segment.
            data_end = match max(data_end, ro_data_end) {
                0 => 0,
                x => {
                    x.checked_add(WORD_SIZE as u32)
                        .expect("Heap base should not overflow")
                        & (!0b11u32)
                }
            };

            let ro_data_memory = FixedMemory::<RO>::from_vec(
                ro_data_base_address,
                ro_data.len() * WORD_SIZE,
                ro_data,
            );

            // this unwrap will never fail for a well-formed elf file, and we've already validated
            data_memory.add_fixed_ro(&ro_data_memory).unwrap();
        }

        // Zero out the public input and public output start locations since no offset is needed for harvard emulator.
        data_memory
            .add_fixed_ro(&FixedMemory::<RO>::from_words(0x80, 8, &[0, 0]))
            .unwrap();

        // Add the public input length to the beginning of the public input.
        let len_bytes = (public_input.len()) as u32;
        let public_input_with_len = [&len_bytes.to_le_bytes()[..], public_input].concat();

        let static_rom_image: BTreeMap<u32, u8> = elf
            .rom_image
            .iter()
            .flat_map(|(addr, &value)| {
                value
                    .to_le_bytes()
                    .into_iter()
                    .enumerate()
                    .map(move |(i, byte)| (addr + i as u32, byte))
            })
            .collect();

        let static_ram_image: BTreeMap<u32, u8> = elf
            .ram_image
            .iter()
            .flat_map(|(addr, &value)| {
                value
                    .to_le_bytes()
                    .into_iter()
                    .enumerate()
                    .map(move |(i, byte)| (addr + i as u32, byte))
            })
            .collect();

        let mut emulator = Self {
            executor: Executor {
                private_input_tape: VecDeque::<u8>::from(private_input.to_vec()),
                base_address: elf.base,
                entrypoint: elf.entry,
                global_clock: 1, // global_clock = 0 captures initalization for memory records
                ..Default::default()
            },
            instruction_memory: FixedMemory::<RO>::from_vec(
                elf.base,
                elf.instructions.len() * WORD_SIZE,
                elf.instructions.clone(),
            ),
            input_memory: FixedMemory::<RO>::from_bytes(0, &public_input_with_len),
            output_memory: VariableMemory::<WO>::default(),
            static_rom_image,
            static_ram_image,
            data_memory,
            memory_stats: MemoryStats::new(data_end, MEMORY_TOP),
        };
        emulator.executor.cpu.pc.value = emulator.executor.entrypoint;
        emulator
    }

    /// Creates a HarvardEmulator from a basic block IR, for simple testing purposes.
    ///
    /// This function initializes a Harvard with a single basic block of instructions.
    /// It's primarily used for testing and simple emulation scenarios.
    pub fn from_basic_blocks(basic_blocks: &Vec<BasicBlock>) -> Self {
        let mut encoded_basic_blocks = Vec::new();
        for block in basic_blocks {
            encoded_basic_blocks.extend(block.encode());
        }

        let mut emulator = Self {
            executor: Executor {
                base_address: ELF_TEXT_START,
                entrypoint: ELF_TEXT_START,
                global_clock: 1, // global_clock = 0 captures initalization for memory records
                ..Default::default()
            },
            instruction_memory: FixedMemory::<RO>::from_vec(
                ELF_TEXT_START,
                encoded_basic_blocks.len() * WORD_SIZE,
                encoded_basic_blocks,
            ),
            data_memory: UnifiedMemory::from(VariableMemory::<RW>::default()),
            ..Default::default()
        };
        emulator.executor.cpu.pc.value = emulator.executor.entrypoint;
        emulator
    }
}

impl Emulator for HarvardEmulator {
    /// Executes a single RISC-V instruction.
    ///
    /// 1. Retrieves the instruction executor function for the given opcode via HashMap.
    /// 2. Executes the instruction using the appropriate executor function.
    /// 3. Updates the program counter (PC) if the instruction is not a branch or jump.
    /// 4. Increments the global clock.
    fn execute_instruction(
        &mut self,
        bare_instruction: &Instruction,
        force_provable_transcript: bool,
    ) -> Result<(InstructionResult, MemoryRecords)> {
        let ((res, (load_ops, store_ops)), accessed_io_memory) = match (
            self.executor
                .instruction_executor
                .get_for_read_input(&bare_instruction.opcode),
            self.executor
                .instruction_executor
                .get_for_write_output(&bare_instruction.opcode),
            self.executor
                .instruction_executor
                .get(&bare_instruction.opcode),
        ) {
            (_, _, _) if bare_instruction.is_system_instruction() => (
                <HarvardEmulator as Emulator>::execute_syscall(
                    &mut self.executor,
                    &mut self.data_memory,
                    None,
                    bare_instruction,
                    force_provable_transcript,
                )?,
                false,
            ),
            (Some(read_input), _, _) => (
                read_input(
                    &mut self.executor.cpu,
                    &mut self.input_memory,
                    bare_instruction,
                )?,
                true,
            ),
            (_, Some(write_output), _) => (
                write_output(
                    &mut self.executor.cpu,
                    &mut self.output_memory,
                    bare_instruction,
                )?,
                true,
            ),
            (_, _, Ok(executor)) => (
                executor(
                    &mut self.executor.cpu,
                    &mut self.data_memory,
                    bare_instruction,
                )?,
                false,
            ),
            (_, _, Err(e)) => return Err(e),
        };

        let mut memory_records = MemoryRecords::new();

        load_ops.clone().iter().for_each(|op| {
            memory_records.insert(op.as_record(self.executor.global_clock));
        });

        store_ops.clone().iter().for_each(|op| {
            memory_records.insert(op.as_record(self.executor.global_clock));
        });

        // Update the memory size statistics.
        if !accessed_io_memory {
            self.memory_stats.update(
                load_ops,
                store_ops,
                self.executor.cpu.registers.read(Register::X2), // Stack pointer
            )?;
        }

        if !bare_instruction.is_branch_or_jump_instruction() {
            self.executor.cpu.pc.step();
        }

        // The global clock will update according to the currency of ZK (constraint?)
        // instead of pure RISC-V cycle count.
        // Right now we don't have information how an instruction cost in ZK, so we just
        // increment the global clock by 1.
        self.executor.global_clock += 1;

        Ok((res, memory_records))
    }

    /// Fetches or decodes a basic block starting from the current PC.
    ///
    /// This function performs the following steps:
    /// 1. Checks if a basic block containing the current PC is already in the cache.
    /// 2. If cached, returns the existing block.
    /// 3. If not cached, decodes a new block, caches it, and returns it.
    ///
    /// # Returns
    /// if success, return a `BasicBlockEntry` starting at the current PC.
    fn fetch_block(&mut self, pc: u32) -> Result<BasicBlockEntry> {
        if let Some(start) = self.executor.basic_block_ref_cache.get(&pc) {
            return Ok(self.executor.basic_block_cache.get(start).unwrap().clone());
        }

        let block = decode_until_end_of_a_block(self.instruction_memory.segment(pc, None));
        if block.is_empty() {
            return Err(VMError::VMOutOfInstructions);
        }

        let entry = BasicBlockEntry::new(pc, block);
        let _ = self.executor.basic_block_cache.insert(pc, entry.clone());

        self.executor
            .basic_block_ref_cache
            .insert(entry.start..entry.end, pc);

        Ok(entry)
    }

    fn get_executor(&self) -> &Executor {
        &self.executor
    }

    fn get_executor_mut(&mut self) -> &mut Executor {
        &mut self.executor
    }

    /// Return a `View` capturing the end-state of the emulator.
    fn finalize(&self) -> View {
        let mut exit_code: Vec<PublicOutputEntry> = Vec::new();
        let mut output_memory: Vec<PublicOutputEntry> = Vec::new();

        if let Ok(bytes) = self.output_memory.segment_bytes(0, None) {
            if let Some((ec, om)) = bytes.split_first_chunk::<4>() {
                exit_code = ec
                    .iter()
                    .enumerate()
                    .map(|(addr, byte)| PublicOutputEntry {
                        address: addr as u32,
                        value: *byte,
                    })
                    .collect();

                output_memory = om
                    .iter()
                    .enumerate()
                    .map(|(addr, byte)| PublicOutputEntry {
                        address: addr as u32,
                        value: *byte,
                    })
                    .collect();
            }
        }

        let public_input: Vec<MemoryInitializationEntry> = self
            .input_memory
            .segment_bytes(0, None)
            .iter()
            .enumerate()
            .map(|(i, byte)| MemoryInitializationEntry {
                address: self.input_memory.base_address + i as u32,
                value: *byte,
            })
            .collect();
        let rom_iter =
            self.static_rom_image
                .iter()
                .map(|(addr, &value)| MemoryInitializationEntry {
                    address: *addr,
                    value,
                });
        // HarvardEmulator doesn't remember the initial content of the static RAM image.
        // When the static RAM image is empty, we know the initial content was also empty, so [Some([])].
        // Otherwise we don't know the initial content so saying [None] instead.
        // This is awkward but it works because HarvardEmulator::finalize() is only used in tests, and the
        // tests are never interested in the non-empty initial static RAM content.
        // Perhaps we'll stop using HarvardEmulator::finalize() and always use LinearEmulator::finalize().
        let ram_iter = if self.static_ram_image.is_empty() {
            Some([].into_iter())
        } else {
            None
        };

        let debug_logs: Vec<Vec<u8>> = if self.get_executor().logs.is_some() {
            self.get_executor().logs.clone().unwrap()
        } else {
            Vec::new()
        };

        let input_size = rom_iter.len() + self.static_ram_image.len() + public_input.len();
        let tracked_ram_size = self
            .memory_stats
            .get_tracked_ram_size(input_size as u32, output_memory.len() as u32)
            as usize;

        View {
            memory_layout: None,
            debug_logs,
            program_memory: ProgramInfo {
                initial_pc: self.executor.entrypoint,
                program: self
                    .instruction_memory
                    .segment(self.executor.base_address, None)
                    .iter()
                    .enumerate()
                    .map(|(pc_offset, instruction)| ProgramMemoryEntry {
                        pc: self.executor.base_address + (pc_offset * WORD_SIZE) as u32,
                        instruction_word: *instruction,
                    })
                    .collect(),
            },
            // Only if ram_iter = Some(...) we know the initial memory for sure. Otherwise returning None.
            initial_memory: ram_iter.map(|ram_iter| {
                rom_iter
                    .into_iter()
                    .chain(ram_iter)
                    .chain(public_input)
                    .collect()
            }),
            tracked_ram_size,
            exit_code,
            output_memory,
            associated_data: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct LinearEmulator {
    // The core execution components
    pub executor: Executor,

    // The unified index for the program instruction memory segment
    instruction_index: (usize, usize),

    // The unified index for the public input memory segment
    public_input_index: (usize, usize),

    // The unified index for the location data for public IO
    public_io_location_index: (usize, usize),

    /// The unified index for the read-only statically allocated region in elf
    static_rom_image_index: Option<(usize, usize)>,

    /// Initial snapshot of the static ram image
    initial_static_ram_image: BTreeMap<u32, u8>,

    // The memory layout
    pub memory_layout: LinearMemoryLayout,

    // The linear memory
    pub memory: UnifiedMemory,

    pub precompile_metadata: HashMap<String, Vec<u32>>,
}

impl LinearEmulator {
    pub fn from_harvard(
        emulator_harvard: &HarvardEmulator,
        compiled_elf: ElfFile,
        ad: &[u8],
        private_input: &[u8],
    ) -> Result<Self> {
        // Reminder!: Add feature flag to control pre-populating output memory.
        // This allows flexibility in the consistency argument used by the prover.

        let public_input = emulator_harvard
            .input_memory
            .segment_bytes(WORD_SIZE as u32, None); // exclude the first word which is the length
        let output_memory = emulator_harvard.output_memory.segment_bytes(0, None)?; // grab the whole output segment, exit code included

        // Replace custom instructions `rin` and `wou` with `lw` and `sw`.
        let instructions = compiled_elf
            .instructions
            .iter()
            .map(|instr| {
                super::convert_instruction(&emulator_harvard.executor.instruction_executor, instr)
            })
            .collect();

        let elf = ElfFile {
            instructions,
            ..compiled_elf
        };

        // Create an optimized memory layout using memory statistics from the first pass.
        let memory_layout = emulator_harvard
            .memory_stats
            .create_optimized_layout(
                ((elf.instructions.len()
                    + WORD_SIZE
                    + elf.rom_image.len()
                    + WORD_SIZE
                    + elf.ram_image.len())
                    * WORD_SIZE) as u32,
                ad.len() as u32,
                public_input.len() as u32,
                (output_memory.len() - WORD_SIZE) as u32, // Exclude the first word which is the exit code
            )
            .unwrap();

        Ok(Self::from_elf(
            memory_layout,
            ad,
            &elf,
            public_input.as_slice(),
            private_input,
        ))
    }

    /// Creates a Linear Emulator from an ELF file.
    ///
    /// This function initializes a Linear Emulator with the provided ELF file, memory layout,
    /// and input data. It sets up the memory segments according to the ELF file structure
    /// and the specified memory layout.
    ///
    /// # Panics
    ///
    /// This function will panic if the provided ElfFile is not well-formed, or if the memory
    /// layout is not compatible with the ELF file.
    pub fn from_elf(
        memory_layout: LinearMemoryLayout,
        ad: &[u8],
        elf: &ElfFile,
        public_input: &[u8],
        private_input: &[u8],
    ) -> Self {
        let mut memory = UnifiedMemory::default();

        // nb: unwraps below will never fail for a well-formed elf file, and we've already validated

        let code_start = memory_layout.program_start();

        let code_memory = FixedMemory::<RO>::from_vec(
            code_start,
            elf.instructions.len() * WORD_SIZE,
            elf.instructions.clone(),
        );
        let instruction_index = memory.add_fixed_ro(&code_memory).unwrap();

        let elf_rom_image_index = if elf.rom_image.is_empty() {
            None
        } else {
            let ro_data_base_address: u32 = *elf.rom_image.first_key_value().unwrap().0;
            let ro_data_len = (*elf.rom_image.keys().max().unwrap() as usize + WORD_SIZE
                - ro_data_base_address as usize)
                / WORD_SIZE;
            let mut ro_data: Vec<u32> = vec![0; ro_data_len];

            for (addr, &value) in &elf.rom_image {
                ro_data[(addr - ro_data_base_address) as usize] = value;
            }

            let ro_data_memory = FixedMemory::<RO>::from_vec(
                ro_data_base_address,
                ro_data.len() * WORD_SIZE,
                ro_data,
            );

            Some(memory.add_fixed_ro(&ro_data_memory).unwrap())
        };

        let _elf_ram_image_index = if elf.ram_image.is_empty() {
            None
        } else {
            let data_base_address: u32 = *elf.ram_image.first_key_value().unwrap().0;
            let data_len = (*elf.ram_image.keys().max().unwrap() as usize + WORD_SIZE
                - data_base_address as usize)
                / WORD_SIZE;
            let mut data: Vec<u32> = vec![0; data_len];

            for (addr, &value) in &elf.ram_image {
                data[((addr - data_base_address) as usize) / WORD_SIZE] = value;
            }

            let data_memory =
                FixedMemory::<RW>::from_vec(data_base_address, data.len() * WORD_SIZE, data);

            Some(memory.add_fixed_rw(&data_memory).unwrap())
        };

        // Add the public input length to the beginning of the public input.
        let len_bytes = public_input.len() as u32;
        let public_input_with_len = [&len_bytes.to_le_bytes()[..], public_input].concat();

        let input_len =
            (memory_layout.public_input_end() - memory_layout.public_input_start()) as usize;
        assert_eq!(word_align!(public_input_with_len.len()), input_len);
        let input_memory = FixedMemory::<RO>::from_bytes(
            memory_layout.public_input_start(),
            &public_input_with_len,
        );
        let public_input_index = memory.add_fixed_ro(&input_memory).unwrap();

        let ad_len = (memory_layout.ad_end() - memory_layout.ad_start()) as usize;
        assert_eq!(ad_len, word_align!(ad.len()));
        if ad_len > 0 {
            let ad_memory = FixedMemory::<NA>::from_bytes(memory_layout.ad_start(), ad);
            let _ = memory.add_fixed_na(&ad_memory).unwrap();
        }

        let output_len = (memory_layout.public_output_end() - memory_layout.exit_code()) as usize; // we include the exit code in the output segment
        if output_len > 0 {
            let init = vec![0; output_len / WORD_SIZE];
            let output_memory =
                FixedMemory::<WO>::from_vec(memory_layout.exit_code(), output_len, init);
            let _ = memory.add_fixed_wo(&output_memory).unwrap();
        }

        let heap_len = (memory_layout.heap_end() - memory_layout.heap_start()) as usize;
        if heap_len > 0 {
            let init = vec![0; heap_len / WORD_SIZE];
            let heap_memory =
                FixedMemory::<RW>::from_vec(memory_layout.heap_start(), heap_len, init);
            let _ = memory.add_fixed_rw(&heap_memory).unwrap();
        }

        let stack_len = (memory_layout.stack_top() - memory_layout.stack_bottom()) as usize;
        if stack_len > 0 {
            let init = vec![0; stack_len / WORD_SIZE];
            let stack_memory =
                FixedMemory::<RW>::from_vec(memory_layout.stack_bottom(), stack_len, init);
            let _ = memory.add_fixed_rw(&stack_memory).unwrap();
        }

        // Add the public input and public output start locations.
        let public_io_location_index = memory
            .add_fixed_ro(&FixedMemory::<RO>::from_words(
                0x80,
                8,
                &[
                    memory_layout.public_input_start(),
                    memory_layout.exit_code(), // the exit code is the first word of the output
                ],
            ))
            .unwrap();

        let initial_static_ram_image: BTreeMap<u32, u8> = elf
            .ram_image
            .iter()
            .flat_map(|(addr, &value)| {
                value
                    .to_le_bytes()
                    .into_iter()
                    .enumerate()
                    .map(move |(i, byte)| (addr + i as u32, byte))
            })
            .collect();

        let mut emulator = Self {
            executor: Executor {
                private_input_tape: VecDeque::<u8>::from(private_input.to_vec()),
                base_address: code_start,
                entrypoint: code_start + (elf.entry - elf.base),
                global_clock: 1, // global_clock = 0 captures initalization for memory records
                ..Default::default()
            },
            instruction_index,
            public_input_index,
            public_io_location_index,
            static_rom_image_index: elf_rom_image_index,
            initial_static_ram_image,
            memory_layout,
            memory,
            ..Default::default()
        };
        emulator.executor.cpu.pc.value = emulator.executor.entrypoint;
        emulator
    }
}

impl Emulator for LinearEmulator {
    /// Executes a single RISC-V instruction.
    ///
    /// 1. Retrieves the instruction executor function for the given opcode via HashMap.
    /// 2. Executes the instruction using the appropriate executor function.
    /// 3. Updates the program counter (PC) if the instruction is not a branch or jump.
    /// 4. Increments the global clock.
    fn execute_instruction(
        &mut self,
        bare_instruction: &Instruction,
        _force_second_pass: bool, // Linear Emulator always does second pass
    ) -> Result<(InstructionResult, MemoryRecords)> {
        let (res, (load_ops, store_ops)) = match (
            self.executor
                .instruction_executor
                .get_for_read_input(&bare_instruction.opcode),
            self.executor
                .instruction_executor
                .get_for_write_output(&bare_instruction.opcode),
            self.executor
                .instruction_executor
                .get(&bare_instruction.opcode),
        ) {
            (_, _, _) if bare_instruction.is_system_instruction() => {
                <HarvardEmulator as Emulator>::execute_syscall(
                    &mut self.executor,
                    &mut self.memory,
                    Some(self.memory_layout),
                    bare_instruction,
                    true,
                )?
            }
            (Some(read_input), _, _) => {
                read_input(&mut self.executor.cpu, &mut self.memory, bare_instruction)?
            }
            (_, Some(write_output), _) => {
                write_output(&mut self.executor.cpu, &mut self.memory, bare_instruction)?
            }
            (_, _, Ok(executor)) => {
                executor(&mut self.executor.cpu, &mut self.memory, bare_instruction)?
            }
            (_, _, Err(e)) => return Err(e),
        };

        let mut memory_records = MemoryRecords::new();

        load_ops.iter().for_each(|op| {
            memory_records.insert(op.as_record(self.executor.global_clock));
        });

        store_ops.iter().for_each(|op| {
            memory_records.insert(op.as_record(self.executor.global_clock));
        });

        if !bare_instruction.is_branch_or_jump_instruction() {
            self.executor.cpu.pc.step();
        }

        // The global clock will update according to the currency of ZK (constraint?)
        // instead of pure RISC-V cycle count.
        // Right now we don't have information how an instruction cost in ZK, so we just
        // increment the global clock by 1.
        self.executor.global_clock += 1;

        Ok((res, memory_records))
    }

    /// Fetches or decodes a basic block starting from the current PC.
    ///
    /// This function performs the following steps:
    /// 1. Checks if a basic block containing the current PC is already in the cache.
    /// 2. If cached, returns the existing block.
    /// 3. If not cached, decodes a new block, caches it, and returns it.
    ///
    /// # Returns
    /// if success, return a `BasicBlockEntry` starting at the current PC.
    fn fetch_block(&mut self, pc: u32) -> Result<BasicBlockEntry> {
        if let Some(start) = self.executor.basic_block_ref_cache.get(&pc) {
            return Ok(self.executor.basic_block_cache.get(start).unwrap().clone());
        }

        let block =
            decode_until_end_of_a_block(self.memory.segment(self.instruction_index, pc, None)?);
        if block.is_empty() {
            return Err(VMError::VMOutOfInstructions);
        }

        let entry = BasicBlockEntry::new(pc, block);
        let _ = self.executor.basic_block_cache.insert(pc, entry.clone());

        self.executor
            .basic_block_ref_cache
            .insert(entry.start..entry.end, pc);

        Ok(entry)
    }

    fn get_executor(&self) -> &Executor {
        &self.executor
    }

    fn get_executor_mut(&mut self) -> &mut Executor {
        &mut self.executor
    }

    /// Return a `View` capturing the end-state of the emulator.
    fn finalize(&self) -> View {
        let mut exit_code: Vec<PublicOutputEntry> = Vec::new();
        let mut output_memory: Vec<PublicOutputEntry> = Vec::new();

        if let Ok(bytes) = self.memory.segment_bytes(
            (Modes::WO as usize, 0),
            self.memory_layout.exit_code(),
            Some(self.memory_layout.public_output_end()),
        ) {
            if let Some((ec, om)) = bytes.split_first_chunk::<4>() {
                exit_code = ec
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| PublicOutputEntry {
                        address: self.memory_layout.exit_code() + i as u32,
                        value: *byte,
                    })
                    .collect();

                output_memory = om
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| PublicOutputEntry {
                        address: self.memory_layout.public_output_start() + i as u32,
                        value: *byte,
                    })
                    .collect();
            }
        }

        let public_input_iter = self
            .memory
            .segment(
                self.public_input_index,
                self.memory_layout.public_input_start(),
                Some(self.memory_layout.public_input_end()),
            )
            .expect("Cannot find public input in LinearEmulator")
            .iter()
            .enumerate()
            .flat_map(|(i, word_content)| {
                let base_address =
                    self.memory_layout.public_input_start() + i as u32 * WORD_SIZE as u32;
                let word = word_content.to_le_bytes();
                word.into_iter()
                    .enumerate()
                    .map(move |(j, byte)| MemoryInitializationEntry {
                        address: base_address + j as u32,
                        value: byte,
                    })
            });
        let public_io_loc_iter = self
            .memory
            .segment(self.public_io_location_index, 0x80, None)
            .expect("Cannot find public io location in LinearEmulator")
            .iter()
            .enumerate()
            .flat_map(|(i, word_content)| {
                let base_address = 0x80 + i as u32 * WORD_SIZE as u32;
                let word = word_content.to_le_bytes();
                word.into_iter()
                    .enumerate()
                    .map(move |(j, byte)| MemoryInitializationEntry {
                        address: base_address + j as u32,
                        value: byte,
                    })
            });
        // TODO: avoid creating a BtreeMap and produce an iterator directly
        let rom_initialization = match self.static_rom_image_index {
            None => BTreeMap::new(),
            Some(uidx) => self
                .memory
                .addr_val_bytes(uidx)
                .expect("invalid static_rom_image_index"),
        };
        let rom_iter = rom_initialization
            .iter()
            .map(|(addr, byte)| MemoryInitializationEntry {
                address: *addr,
                value: *byte,
            });
        let ram_initialization = &self.initial_static_ram_image;
        let ram_iter = ram_initialization
            .iter()
            .map(|(addr, byte)| MemoryInitializationEntry {
                address: *addr,
                value: *byte,
            });

        let debug_logs: Vec<Vec<u8>> = if self.get_executor().logs.is_some() {
            self.get_executor().logs.clone().unwrap()
        } else {
            Vec::new()
        };

        let associated_data: Vec<u8> = self
            .memory
            .segment_bytes(
                (Modes::NA as usize, 0),
                self.memory_layout.ad_start(),
                Some(self.memory_layout.ad_end()),
            )
            .unwrap_or_default();

        let tracked_ram_size = self
            .memory_layout
            .tracked_ram_size(self.initial_static_ram_image.len() + rom_initialization.len());

        View {
            memory_layout: Some(self.memory_layout),
            debug_logs,
            program_memory: ProgramInfo {
                // todo: this likely isn't robust, we need to rely on elf.entry,
                //       but it seems to be working with the current runtime
                initial_pc: self.memory_layout.program_start(),
                program: self
                    .memory
                    .segment(
                        self.instruction_index,
                        self.memory_layout.program_start(),
                        None,
                    )
                    .expect("Cannot find program memory in LinearEmulator")
                    .iter()
                    .enumerate()
                    .map(|(pc_offset, instruction)| ProgramMemoryEntry {
                        pc: self.memory_layout.program_start() + (pc_offset * WORD_SIZE) as u32,
                        instruction_word: *instruction,
                    })
                    .collect(),
            },
            initial_memory: Some(
                public_io_loc_iter
                    .into_iter()
                    .chain(rom_iter)
                    .chain(ram_iter)
                    .chain(public_input_iter)
                    .collect(),
            ),
            tracked_ram_size,
            exit_code,
            output_memory,
            associated_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfFile;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode};
    use serial_test::serial;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29),
        ]);
        vec![basic_block]
    }

    #[test]
    #[serial]
    fn test_harvard_emulate_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let mut emulator = HarvardEmulator::from_elf(&elf_file, &[], &[]);

        assert_eq!(emulator.execute(false), Err(VMError::VMExited(0)));
    }

    #[test]
    fn test_harvard_fibonacci() {
        let basic_blocks = setup_basic_block_ir();

        let mut emulator = HarvardEmulator::default();
        basic_blocks.iter().for_each(|basic_block| {
            emulator
                .execute_basic_block(&BasicBlockEntry::new(0, basic_block.clone()), false)
                .unwrap();
        });

        assert_eq!(emulator.executor.cpu.registers[31.into()], 1346269);
    }

    #[test]
    fn test_harvard_set_private_input() {
        let private_input: [u8; 5] = [1, 2, 3, 4, 5];
        let private_input_vec = VecDeque::<u8>::from(vec![1, 2, 3, 4, 5]);

        let mut emulator = HarvardEmulator::default();
        emulator.set_private_input(&private_input);

        assert_eq!(emulator.executor.private_input_tape, private_input_vec);
    }

    #[test]
    fn test_harvard_from_basic_block() {
        let basic_blocks = setup_basic_block_ir();
        let mut emulator = HarvardEmulator::from_basic_blocks(&basic_blocks);

        assert_eq!(emulator.execute(false), Err(VMError::VMOutOfInstructions));
    }

    #[test]
    #[serial]
    fn test_linear_emulate_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let mut emulator =
            LinearEmulator::from_elf(LinearMemoryLayout::default(), &[], &elf_file, &[], &[]);

        assert_eq!(emulator.execute(false), Err(VMError::VMExited(0)));
    }

    #[test]
    fn test_linear_fibonacci() {
        let basic_blocks = setup_basic_block_ir();

        let mut emulator = LinearEmulator::default();
        basic_blocks.iter().for_each(|basic_block| {
            emulator
                .execute_basic_block(&BasicBlockEntry::new(0, basic_block.clone()), false)
                .unwrap();
        });

        assert_eq!(emulator.executor.cpu.registers[31.into()], 1346269);
    }

    #[test]
    fn test_linear_set_private_input() {
        let private_input: [u8; 5] = [1, 2, 3, 4, 5];
        let private_input_vec = VecDeque::<u8>::from(vec![1, 2, 3, 4, 5]);

        let mut emulator = LinearEmulator::default();
        emulator.set_private_input(&private_input);

        assert_eq!(emulator.executor.private_input_tape, private_input_vec);
    }

    #[test]
    fn test_unimplemented_instruction() {
        let op = Opcode::new(0, None, None, "unsupported");
        let basic_block_entry = BasicBlockEntry::new(
            0,
            BasicBlock::new(vec![Instruction::new_ir(op.clone(), 1, 0, 1)]),
        );
        let mut emulator = HarvardEmulator::default();
        let res = emulator.execute_basic_block(&basic_block_entry, false);

        assert_eq!(res, Err(VMError::UndefinedInstruction(op.clone())));

        let mut emulator = LinearEmulator::default();
        let res = emulator.execute_basic_block(&basic_block_entry, false);

        assert_eq!(res, Err(VMError::UndefinedInstruction(op)));
    }
}
