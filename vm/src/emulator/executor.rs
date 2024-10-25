//! # RISC-V Emulator Executor
//!
//! This module contains the core execution logic for the RISC-V emulator.
//! It defines the `Emulator` struct and its associated methods for executing
//! RISC-V instructions and managing the emulator's state.
//!
//! ## Key Components
//!
//! - `Emulator`: The main struct representing the emulator's state and functionality.
//! - `execute_instruction`: Method to execute a single RISC-V instruction.
//! - `fetch_block`: Method to fetch or decode a basic block of instructions.
//! - `execute_basic_block`: Method to execute a basic block of instructions.
//! - `execute`: Main execution loop of the emulator.
//!
//! ## Basic Block Execution
//!
//! The emulator uses a basic block approach for efficiency:
//! 1. Fetch or decode a basic block starting from the current PC.
//! 2. Execute all instructions in the block sequentially.
//! 3. Update the PC and continue with the next block.
//!
//! ## Error Handling
//!
//! The emulator uses a `Result` type for error handling, with custom error types
//! defined in the `error` module.
//!
//! ## Examples
//!
//! ### Creating and Running an Emulator
//!
//! ```rust
//! use nexus_vm::elf::ElfFile;
//! use nexus_vm::emulator::{Emulator, HarvardEmulator};
//!
//! // Load an ELF file
//! let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
//!
//! // Create an emulator instance
//! let mut emulator = HarvardEmulator::from_elf(elf_file, &[], &[]);
//!
//! // Run the emulator
//! match emulator.execute() {
//!     Ok(_) => println!("Program executed successfully"),
//!     Err(e) => println!("Execution error: {:?}", e),
//! }
//! ```
//!
//! ### Executing a Basic Block
//!
//! ```rust
//! use nexus_vm::riscv::{BasicBlock, Instruction, Opcode, BuiltinOpcode, InstructionType};
//! use nexus_vm::emulator::{Emulator, HarvardEmulator};
//!
//! // Create a basic block with some instructions
//! let basic_block = BasicBlock::new(vec![
//!     Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5, InstructionType::IType),  // x1 = x0 + 5
//!     Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 10, InstructionType::IType), // x2 = x0 + 10
//!     Instruction::new(Opcode::from(BuiltinOpcode::ADD), 3, 1, 2, InstructionType::RType),   // x3 = x1 + x2
//! ]);
//!
//! let mut emulator = HarvardEmulator::default();
//! emulator.execute_basic_block(&basic_block).unwrap();
//!
//! assert_eq!(emulator.executor.cpu.registers[3.into()], 15); // x3 should be 15
//! ```
//!

use std::cmp::max;
use std::collections::{btree_map, BTreeMap, HashMap, VecDeque};

use super::{layout::LinearMemoryLayout, registry::InstructionExecutorRegistry};
use crate::{
    cpu::{instructions::InstructionResult, Cpu},
    elf::ElfFile,
    error::{Result, VMError},
    memory::{
        FixedMemory, LoadOps, MemAccessSize, MemoryProcessor, MemoryRecords, StoreOps,
        UnifiedMemory, VariableMemory, NA, RO, RW, WO,
    },
    riscv::{decode_until_end_of_a_block, BasicBlock, Instruction, Opcode},
    system::SyscallInstruction,
    WORD_SIZE,
};
use nexus_common::cpu::InstructionExecutor;

pub type MemoryTranscript = Vec<MemoryRecords>;

#[derive(Debug, Default)]
pub struct Executor {
    // The CPU
    pub cpu: Cpu,

    // Instruction Executor
    instruction_executor: InstructionExecutorRegistry,

    // The private input tape as a FIFO queue.
    pub private_input_tape: VecDeque<u8>,

    // The global clock counter
    pub global_clock: usize,

    // Basic block cache to improve performance
    basic_block_cache: BTreeMap<u32, BasicBlock>,

    // The base address of the program
    #[allow(unused)]
    base_address: u32,

    // The entrypoint of the program
    entrypoint: u32,

    // The cycles tracker: (name, (cycle_count, occurrence))
    pub cycle_tracker: HashMap<String, (usize, usize)>,
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
}

pub trait Emulator {
    /// Execute a system call instruction
    ///
    /// 1. Decode the system call parameters from register a0-a6
    /// 2. Read necessary data from memory
    /// 3. Execute the system call, modify the emulator if necessary
    /// 4. Write results back to memory
    /// 5. Update CPU state, the return result is stored in register a0
    fn execute_syscall(
        executor: &mut Executor,
        memory: &mut impl MemoryProcessor,
        memory_layout: Option<LinearMemoryLayout>,
        bare_instruction: &Instruction,
    ) -> Result<(InstructionResult, MemoryRecords)> {
        let mut syscall_instruction = SyscallInstruction::decode(bare_instruction, &executor.cpu)?;
        syscall_instruction.memory_read(memory)?;
        syscall_instruction.execute(executor, memory, memory_layout)?;
        syscall_instruction.memory_write(memory)?;
        syscall_instruction.write_back(&mut executor.cpu);

        // Safety: during the first pass, the Write and CycleCount syscalls can read from memory
        //         however, during the second pass these are no-ops, so we never need a record
        Ok((None, MemoryRecords::new()))
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
    ) -> Result<(InstructionResult, MemoryRecords)>;

    /// Fetches or decodes a basic block starting from the current PC.
    ///
    /// This function performs the following steps:
    /// 1. Checks if the basic block at the current PC is already in the cache.
    /// 2. If cached, returns the existing block.
    /// 3. If not cached, decodes a new block, caches it, and returns it.
    ///
    /// # Returns
    /// if success, return a clone of `BasicBlock` starting at the current PC.
    fn fetch_block(&mut self, pc: u32) -> Result<BasicBlock>;

    /// Return a reference to the internal executor component used by the emulator.
    fn get_executor(&self) -> &Executor;

    /// Return a mutable reference to the internal executor component used by the emulator.
    fn get_executor_mut(&mut self) -> &mut Executor;

    /// Execute an entire basic block.
    fn execute_basic_block(
        &mut self,
        basic_block: &BasicBlock,
    ) -> Result<(Vec<InstructionResult>, MemoryTranscript)> {
        #[cfg(debug_assertions)]
        basic_block.print_with_offset(self.get_executor().cpu.pc.value as usize);

        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        // Execute the instructions in the basic block
        for instruction in basic_block.0.iter() {
            let (res, mem) = self.execute_instruction(instruction)?;
            results.push(res);
            transcript.push(mem);
        }

        Ok((results, transcript))
    }

    /// Execute an entire program.
    fn execute(&mut self) -> Result<(Vec<InstructionResult>, MemoryTranscript)> {
        let mut results: Vec<InstructionResult> = Vec::new();
        let mut transcript: MemoryTranscript = Vec::new();

        loop {
            let basic_block = self.fetch_block(self.get_executor().cpu.pc.value)?;
            let (res, mem) = self.execute_basic_block(&basic_block)?;

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
}

#[derive(Debug)]
pub struct HarvardEmulator {
    // The core execution components
    pub executor: Executor,

    // The instruction memory image
    instruction_memory: FixedMemory<RO>,

    // The input memory image
    #[allow(unused)]
    input_memory: FixedMemory<RO>,

    // The output memory image
    #[allow(unused)]
    output_memory: VariableMemory<WO>,

    // A combined read-only (in part) and read-write (in part) memory image
    pub data_memory: UnifiedMemory,
}

impl Default for HarvardEmulator {
    fn default() -> Self {
        // a suitable default for testing
        Self {
            executor: Executor::default(),
            instruction_memory: FixedMemory::<RO>::new(0, 0x1000),
            input_memory: FixedMemory::<RO>::new(0, 0x1000),
            output_memory: VariableMemory::<WO>::default(),
            data_memory: UnifiedMemory::default(),
        }
    }
}

impl HarvardEmulator {
    pub fn from_elf(elf: ElfFile, public_input: &[u32], private_input: &[u8]) -> Self {
        // the stack and heap will also be stored in this variable memory segment
        let mut data_memory = UnifiedMemory::from(VariableMemory::<RW>::from(elf.ram_image));

        if !elf.rom_image.is_empty() {
            let ro_data_base_address: u32 = *elf.rom_image.first_key_value().unwrap().0;
            let mut ro_data: Vec<u32> = vec![
                0;
                *elf.rom_image.keys().max().unwrap_or(&0) as usize + 1
                    - ro_data_base_address as usize
            ];

            for (addr, &value) in &elf.rom_image {
                ro_data[(addr - ro_data_base_address) as usize] = value;
            }

            let ro_data_memory = FixedMemory::<RO>::from_vec(
                ro_data_base_address,
                ro_data.len() * WORD_SIZE,
                ro_data,
            );

            // this unwrap will never fail for a well-formed elf file, and we've already validated
            data_memory.add_fixed_ro(&ro_data_memory).unwrap();
        }

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
                elf.instructions,
            ),
            input_memory: FixedMemory::<RO>::from_slice(
                0,
                1 + public_input.len() * WORD_SIZE,
                &[&[public_input.len() as u32; 1], public_input].concat(),
            ),
            output_memory: VariableMemory::<WO>::default(),
            data_memory,
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
    ) -> Result<(InstructionResult, MemoryRecords)> {
        if bare_instruction.is_system_instruction() {
            let _ = <HarvardEmulator as Emulator>::execute_syscall(
                &mut self.executor,
                &mut self.data_memory,
                None,
                bare_instruction,
            )?;
        } else {
            let _ = match self
                .executor
                .instruction_executor
                .get(&bare_instruction.opcode)
            {
                Ok(executor) => executor(
                    &mut self.executor.cpu,
                    &mut self.data_memory,
                    bare_instruction,
                )?,
                Err(VMError::UnimplementedInstruction(inst)) => {
                    return Err(VMError::UnimplementedInstructionAt(
                        inst,
                        self.executor.cpu.pc.value,
                    ));
                }
                Err(e) => return Err(e),
            };
        }

        if !bare_instruction.is_branch_or_jump_instruction() {
            self.executor.cpu.pc.step();
        }

        // The global clock will update according to the currency of ZK (constraint?)
        // instead of pure RISC-V cycle count.
        // Right now we don't have information how an instruction cost in ZK, so we just
        // increment the global clock by 1.
        self.executor.global_clock += 1;

        // nb: we don't need any sort of operation records from the first pass
        Ok((None, MemoryRecords::new()))
    }

    /// Fetches or decodes a basic block starting from the current PC.
    ///
    /// This function performs the following steps:
    /// 1. Checks if the basic block at the current PC is already in the cache.
    /// 2. If cached, returns the existing block.
    /// 3. If not cached, decodes a new block, caches it, and returns it.
    ///
    /// # Returns
    /// if success, return a clone of `BasicBlock` starting at the current PC.
    fn fetch_block(&mut self, pc: u32) -> Result<BasicBlock> {
        if let btree_map::Entry::Vacant(e) = self.executor.basic_block_cache.entry(pc) {
            let block = decode_until_end_of_a_block(self.instruction_memory.segment(pc, None));
            if block.is_empty() {
                return Err(VMError::VMOutOfInstructions);
            }
            e.insert(block);
        }
        Ok(self.executor.basic_block_cache.get(&pc).unwrap().clone())
    }

    fn get_executor(&self) -> &Executor {
        &self.executor
    }

    fn get_executor_mut(&mut self) -> &mut Executor {
        &mut self.executor
    }
}

#[derive(Debug, Default)]
pub struct LinearEmulator {
    // The core execution components
    pub executor: Executor,

    // The unified index for the program instruction memory segment
    instruction_index: (usize, usize),

    // A map of memory addresses to the last timestamp when they were accessed
    access_timestamps: HashMap<u32, usize>,

    // The memory layout
    pub memory_layout: LinearMemoryLayout,

    // The linear memory
    pub memory: UnifiedMemory,
}

impl LinearEmulator {
    pub fn from_harvard(
        _memory_layout: LinearMemoryLayout,
        _ad: &[u32],
        _emul: HarvardEmulator,
    ) -> Self {
        // Reminder!: the output linear memory segment should be pre-populated with the contents of the output
        //            harvard memory segment, in order to enable an i/o consistency argument like that of Jolt.
        todo!()
    }

    pub fn from_elf(
        memory_layout: LinearMemoryLayout,
        ad: &[u32],
        elf: ElfFile,
        public_input: &[u32],
        private_input: &[u8],
    ) -> Self {
        let mut memory = UnifiedMemory::default();

        // nb: unwraps below will never fail for a well-formed elf file, and we've already validated

        let code_start = memory_layout.program_start();
        let ro_data_start = code_start + (elf.instructions.len() * WORD_SIZE) as u32;
        let data_start: u32;

        let code_memory = FixedMemory::<RO>::from_vec(
            code_start,
            elf.instructions.len() * WORD_SIZE,
            elf.instructions,
        );
        let instruction_index = memory.add_fixed_ro(&code_memory).unwrap();

        if !elf.rom_image.is_empty() {
            let ro_data_base_address: u32 = *elf.rom_image.first_key_value().unwrap().0;
            let mut ro_data: Vec<u32> = vec![
                0;
                *elf.rom_image.keys().max().unwrap_or(&0) as usize + 1
                    - ro_data_base_address as usize
            ];

            data_start = ro_data_start + (ro_data.len() * WORD_SIZE) as u32;

            for (addr, &value) in &elf.rom_image {
                ro_data[(addr - ro_data_base_address) as usize] = value;
            }

            let ro_data_memory =
                FixedMemory::<RO>::from_vec(ro_data_start, ro_data.len() * WORD_SIZE, ro_data);

            let _ = memory.add_fixed_ro(&ro_data_memory).unwrap();
        } else {
            data_start = ro_data_start;
        }

        if !elf.ram_image.is_empty() {
            let data_base_address: u32 = *elf.ram_image.first_key_value().unwrap().0;
            let mut data: Vec<u32> = vec![
                0;
                *elf.ram_image.keys().max().unwrap_or(&0) as usize + 1
                    - data_base_address as usize
            ];

            for (addr, &value) in &elf.ram_image {
                data[(addr - data_base_address) as usize] = value;
            }

            let data_memory = FixedMemory::<RW>::from_vec(data_start, data.len() * WORD_SIZE, data);

            let _ = memory.add_fixed_rw(&data_memory).unwrap();
        }

        let input_len =
            (memory_layout.public_input_end() - memory_layout.public_input_start()) as usize;
        assert_eq!(input_len, WORD_SIZE + (public_input.len() * WORD_SIZE));
        if input_len > 0 {
            let input_memory = FixedMemory::<RO>::from_slice(
                memory_layout.public_input_start(),
                input_len,
                &[&[public_input.len() as u32; 1], public_input].concat(),
            );
            let _ = memory.add_fixed_ro(&input_memory).unwrap();
        }

        let output_len = (memory_layout.public_output_end() - memory_layout.panic()) as usize; // we include panic in the output segment
        if output_len > 0 {
            let output_memory =
                FixedMemory::<WO>::from_vec(memory_layout.panic(), output_len, vec![0; output_len]);
            let _ = memory.add_fixed_wo(&output_memory).unwrap();
        }

        let heap_len = (memory_layout.heap_end() - memory_layout.heap_start()) as usize;
        let heap_memory =
            FixedMemory::<RW>::from_vec(memory_layout.heap_start(), heap_len, vec![0; heap_len]);
        let _ = memory.add_fixed_rw(&heap_memory).unwrap();

        let stack_len = (memory_layout.stack_top() - memory_layout.stack_bottom()) as usize;
        let stack_memory = FixedMemory::<RW>::from_vec(
            memory_layout.stack_bottom(),
            stack_len,
            vec![0; stack_len],
        );
        let _ = memory.add_fixed_rw(&stack_memory).unwrap();

        let ad_len = (memory_layout.ad_end() - memory_layout.ad_start()) as usize;
        assert_eq!(ad_len, ad.len() * WORD_SIZE);
        if ad_len > 0 {
            let ad_memory = FixedMemory::<NA>::from_slice(memory_layout.ad_start(), ad_len, ad);
            let _ = memory.add_fixed_na(&ad_memory).unwrap();
        }

        let mut emulator = Self {
            executor: Executor {
                private_input_tape: VecDeque::<u8>::from(private_input.to_vec()),
                base_address: code_start,
                entrypoint: code_start + (elf.entry - elf.base),
                global_clock: 1, // global_clock = 0 captures initalization for memory records
                ..Default::default()
            },
            instruction_index,
            memory_layout,
            memory,
            ..Default::default()
        };
        emulator.executor.cpu.pc.value = emulator.executor.entrypoint;
        emulator
    }

    fn manage_timestamps(&mut self, size: &MemAccessSize, address: &u32) -> usize {
        let half_aligned_address = address & !(WORD_SIZE / 2 - 1) as u32;
        let full_aligned_address = address & !(WORD_SIZE - 1) as u32;

        let prev = match size {
            MemAccessSize::Byte => max(
                *self.access_timestamps.get(address).unwrap_or(&0),
                max(
                    *self
                        .access_timestamps
                        .get(&half_aligned_address)
                        .unwrap_or(&0),
                    *self
                        .access_timestamps
                        .get(&full_aligned_address)
                        .unwrap_or(&0),
                ),
            ),
            MemAccessSize::HalfWord => max(
                *self.access_timestamps.get(address).unwrap_or(&0),
                *self
                    .access_timestamps
                    .get(&full_aligned_address)
                    .unwrap_or(&0),
            ),
            MemAccessSize::Word => *self.access_timestamps.get(address).unwrap_or(&0),
        };

        self.access_timestamps
            .insert(*address, self.executor.global_clock);
        prev
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
    ) -> Result<(InstructionResult, MemoryRecords)> {
        let res: InstructionResult;
        let mut memory_records: MemoryRecords;

        if bare_instruction.is_system_instruction() {
            (res, memory_records) = <LinearEmulator as Emulator>::execute_syscall(
                &mut self.executor,
                &mut self.memory,
                Some(self.memory_layout),
                bare_instruction,
            )?;
        } else {
            let load_ops: LoadOps;
            let store_ops: StoreOps;

            (res, (load_ops, store_ops)) = match self
                .executor
                .instruction_executor
                .get(&bare_instruction.opcode)
            {
                Ok(executor) => {
                    executor(&mut self.executor.cpu, &mut self.memory, bare_instruction)?
                }
                Err(VMError::UnimplementedInstruction(inst)) => {
                    return Err(VMError::UnimplementedInstructionAt(
                        inst,
                        self.executor.cpu.pc.value,
                    ));
                }
                Err(e) => return Err(e),
            };

            memory_records = MemoryRecords::new();

            load_ops.iter().for_each(|op| {
                let size = op.get_size();
                let address = op.get_address();

                memory_records.insert(op.as_record(
                    self.executor.global_clock,
                    self.manage_timestamps(&size, &address),
                ));
            });

            store_ops.iter().for_each(|op| {
                let size = op.get_size();
                let address = op.get_address();

                memory_records.insert(op.as_record(
                    self.executor.global_clock,
                    self.manage_timestamps(&size, &address),
                ));
            });
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
    /// 1. Checks if the basic block at the current PC is already in the cache.
    /// 2. If cached, returns the existing block.
    /// 3. If not cached, decodes a new block, caches it, and returns it.
    ///
    /// # Returns
    /// if success, return a clone of `BasicBlock` starting at the current PC.
    fn fetch_block(&mut self, pc: u32) -> Result<BasicBlock> {
        if let btree_map::Entry::Vacant(e) = self.executor.basic_block_cache.entry(pc) {
            let block = decode_until_end_of_a_block(self.memory.segment(
                self.instruction_index,
                pc,
                None,
            )?);
            if block.is_empty() {
                return Err(VMError::VMOutOfInstructions);
            }
            e.insert(block);
        }
        Ok(self.executor.basic_block_cache.get(&pc).unwrap().clone())
    }

    fn get_executor(&self) -> &Executor {
        &self.executor
    }

    fn get_executor_mut(&mut self) -> &mut Executor {
        &mut self.executor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfFile;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode};

    #[test]
    fn test_harvard_emulate_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let mut emulator = HarvardEmulator::from_elf(elf_file, &[], &[]);

        assert_eq!(emulator.execute(), Err(VMError::VMExited(0)));
    }

    #[test]
    #[rustfmt::skip]
    fn test_harvard_fibonacci() {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1, InstructionType::IType),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29, InstructionType::RType),
        ]);

        let mut emulator = HarvardEmulator::default();
        emulator.execute_basic_block(&basic_block).unwrap();

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
    fn test_linear_emulate_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let mut emulator =
            LinearEmulator::from_elf(LinearMemoryLayout::default(), &[], elf_file, &[], &[]);

        assert_eq!(emulator.execute(), Err(VMError::VMExited(0)));
    }

    #[test]
    #[rustfmt::skip]
    fn test_linear_fibonacci() {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1, InstructionType::IType),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29, InstructionType::RType),
        ]);

        let mut emulator = LinearEmulator::default();
        emulator.execute_basic_block(&basic_block).unwrap();

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
}
