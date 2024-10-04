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
//! use nexus_vm::emulator::Emulator;
//!
//! // Load an ELF file
//! let elf_file = ElfFile::from_path("test/helloworld.elf").expect("Unable to load ELF file");
//!
//! // Create an emulator instance
//! let mut emulator = Emulator::from_elf(elf_file);
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
//! use nexus_vm::emulator::Emulator;
//!
//! // Create a basic block with some instructions
//! let basic_block = BasicBlock::new(vec![
//!     Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5, InstructionType::IType),  // x1 = x0 + 5
//!     Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 10, InstructionType::IType), // x2 = x0 + 10
//!     Instruction::new(Opcode::from(BuiltinOpcode::ADD), 3, 1, 2, InstructionType::RType),   // x3 = x1 + x2
//! ]);
//!
//! let mut emulator = Emulator::default();
//! emulator.execute_basic_block(&basic_block).unwrap();
//!
//! assert_eq!(emulator.cpu.registers[3.into()], 15); // x3 should be 15
//! ```
//!

use std::collections::{btree_map, BTreeMap, HashMap, VecDeque};

use super::registry::InstructionExecutorRegistry;
use crate::{
    cpu::{Cpu, InstructionExecutor},
    elf::{ElfFile, WORD_SIZE},
    error::{Result, VMError},
    memory::{FixedMemory, VariableMemory},
    riscv::{decode_until_end_of_a_block, BasicBlock, Instruction, Opcode},
    system::SyscallInstruction,
};

#[derive(Debug)]
pub struct Emulator {
    // The CPU
    pub cpu: Cpu,

    // The instruction memory image
    instruction_memory: FixedMemory,

    // Instruction Executor
    instruction_executor: InstructionExecutorRegistry,

    // The writable memory image
    pub data_memory: VariableMemory,

    // The private input memory FIFO queues.
    pub private_input_memory: VecDeque<u8>,

    // The global clock counter
    pub global_clock: usize,

    // Basic block cache to improve performance
    basic_block_cache: BTreeMap<u32, BasicBlock>,

    // The base address of the program
    base_address: u32,

    // The entrypoint of the program
    entrypoint: u32,

    /// The cycles tracker: (name, (cycle_count, occurrence))
    pub cycle_tracker: HashMap<String, (usize, usize)>,
}

impl Default for Emulator {
    fn default() -> Self {
        Self {
            cpu: Cpu::default(),
            instruction_memory: FixedMemory::new(1024),
            instruction_executor: InstructionExecutorRegistry::default(),
            data_memory: VariableMemory::default(),
            private_input_memory: VecDeque::default(),
            global_clock: 0,
            basic_block_cache: BTreeMap::default(),
            base_address: 0,
            entrypoint: 0,
            cycle_tracker: HashMap::new(),
        }
    }
}

impl Emulator {
    pub fn from_elf(elf: ElfFile) -> Self {
        // We assume the compiler will make sure that there is no execution code
        // in the readonly memory region (elf.rom_image), thus, we simplify the memory
        // model by concatenating the rom_image and ram_image into a single memory image.
        let mut combined_memory = elf.ram_image;
        combined_memory.extend(elf.rom_image);
        let mut emulator = Self {
            instruction_memory: FixedMemory::from_vec(elf.instructions.len(), elf.instructions),
            data_memory: VariableMemory::from(combined_memory),
            base_address: elf.base,
            entrypoint: elf.entry,
            ..Default::default()
        };
        emulator.cpu.pc.value = emulator.entrypoint;
        emulator
    }

    /// Execute a system call instruction
    ///
    /// 1. Decode the system call parameters from register a0-a6
    /// 2. Read necessary data from memory
    /// 3. Execute the system call, modify the emulator if necessary
    /// 4. Write results back to memory
    /// 5. Update CPU state, the return result is stored in register a0
    fn execute_syscall(&mut self, bare_instruction: &Instruction) -> Result<()> {
        let mut syscall_instruction = SyscallInstruction::decode(bare_instruction, &self.cpu)?;
        syscall_instruction.memory_read(&self.data_memory)?;
        syscall_instruction.execute(self)?;
        syscall_instruction.memory_write(&mut self.data_memory)?;
        syscall_instruction.write_back(&mut self.cpu);

        Ok(())
    }

    /// Executes a single RISC-V instruction.
    ///
    /// 1. Retrieves the instruction executor function for the given opcode via HashMap.
    /// 2. Executes the instruction using the appropriate executor function.
    /// 3. Updates the program counter (PC) if the instruction is not a branch or jump.
    /// 4. Increments the global clock.
    fn execute_instruction(&mut self, bare_instruction: &Instruction) -> Result<()> {
        if bare_instruction.is_system_instruction() {
            self.execute_syscall(bare_instruction)?;
        } else if let Some(executor) = self
            .instruction_executor
            .into_variable_memory(&bare_instruction.opcode)
        {
            executor(&mut self.cpu, &mut self.data_memory, bare_instruction)?;
        } else {
            return Err(VMError::UnimplementedInstruction(self.cpu.pc.value));
        }

        if !bare_instruction.is_branch_or_jump_instruction() {
            self.cpu.pc.step();
        }

        // The global clock will update according to the currency of ZK (constraint?)
        // instead of pure RISC-V cycle count.
        // Right now we don't have information how an instruction cost in ZK, so we just
        // increment the global clock by 1.
        self.global_clock += 1;

        Ok(())
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
        if let btree_map::Entry::Vacant(e) = self.basic_block_cache.entry(pc) {
            let address = (pc - self.base_address) / WORD_SIZE;
            let block = decode_until_end_of_a_block(
                self.instruction_memory.segment(address as usize, None),
            );
            if block.is_empty() {
                return Err(VMError::VMStopped);
            }
            e.insert(block);
        }
        Ok(self.basic_block_cache.get(&pc).unwrap().clone())
    }

    pub fn execute_basic_block(&mut self, basic_block: &BasicBlock) -> Result<()> {
        #[cfg(debug_assertions)]
        basic_block.print_with_offset(self.cpu.pc.value as usize);

        // Execute the instructions in the basic block
        for instruction in basic_block.0.iter() {
            self.execute_instruction(instruction)?;
        }

        Ok(())
    }

    pub fn execute(&mut self) -> Result<()> {
        loop {
            let basic_block = self.fetch_block(self.cpu.pc.value)?;
            self.execute_basic_block(&basic_block)?;
        }
    }

    /// Adds a new opcode and its corresponding execution function to the emulator.
    pub fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<()> {
        self.instruction_executor.add_opcode::<IE>(op)
    }

    /// Set Private Input to the private input memory
    pub fn set_private_input(mut self, private_input: VecDeque<u8>) -> Self {
        self.private_input_memory = private_input;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfFile;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode};

    #[test]
    fn test_emulate_instructions() {
        let elf_file = ElfFile::from_path("test/helloworld.elf").expect("Unable to load ELF file");
        let mut emulator = Emulator::from_elf(elf_file);

        assert_eq!(
            emulator.execute(),
            Err(VMError::UnimplementedInstruction(48))
        );
    }

    #[test]
    fn test_emulate_native_binary() {
        let elf_file = ElfFile::from_path("../tests/integration_tests/fib_10.elf").expect("Unable to load ELF file");
        let mut emulator = Emulator::from_elf(elf_file);

        assert_eq!(
            emulator.execute(),
            Err(VMError::UnimplementedInstruction(71128))
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_fibonacci() {
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

        let mut emulator = Emulator::default();
        emulator.execute_basic_block(&basic_block).unwrap();

        assert_eq!(emulator.cpu.registers[31.into()], 1346269);
    }

    #[test]
    fn test_set_private_input() {
        let private_input = VecDeque::from(vec![1, 2, 3, 4, 5]);
        let emulator_with_input = Emulator::default().set_private_input(private_input.clone());

        assert_eq!(emulator_with_input.private_input_memory, private_input);
    }
}
