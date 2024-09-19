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
//! let elf_file = ElfFile::from_path("test/hello.elf").expect("Unable to load ELF file");
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
//! use nexus_vm::riscv::{BasicBlock, Instruction, Opcode, InstructionType};
//! use nexus_vm::emulator::Emulator;
//!
//! // Create a basic block with some instructions
//! let basic_block = BasicBlock::new(vec![
//!     Instruction::new(Opcode::ADDI, 1, 0, 5, InstructionType::IType),  // x1 = x0 + 5
//!     Instruction::new(Opcode::ADDI, 2, 0, 10, InstructionType::IType), // x2 = x0 + 10
//!     Instruction::new(Opcode::ADD, 3, 1, 2, InstructionType::RType),   // x3 = x1 + x2
//! ]);
//!
//! let mut emulator = Emulator::default();
//! emulator.execute_basic_block(&basic_block).unwrap();
//!
//! assert_eq!(emulator.cpu.registers[3.into()], 15); // x3 should be 15
//! ```
//!
//! ## Extensibility
//!
//! The emulator supports adding custom opcodes and their corresponding execution functions at runtime.
//! This feature allows for extending the instruction set without modifying the core emulator code.
//!
//! To add a new opcode:
//!
//! 1. Define a custom execution function that implements the `InstructionExecutorFn` signature.
//! 2. Use the `add_opcode` method of the `Emulator` struct to register the new opcode and its execution function.
//!
//! Example:
//!
//! ```
//! use nexus_vm::{cpu::Cpu, memory::Memory, emulator::Emulator, riscv::{Opcode, Instruction}, error::Result};
//! let custom_opcode = Opcode::CUSTOM0;
//! let custom_function = |_cpu: &mut Cpu, _data_memory: &mut Memory, instruction: &Instruction| -> Result<()> {
//!     // Implement custom instruction logic here
//!     Ok(())
//! };
//! let emulator = Emulator::default().add_opcode(custom_opcode, custom_function).unwrap();
//! ```
//!
//! Note:
//! - The `add_opcode` method checks for duplicate opcodes and returns an error if the opcode already exists.
//! - Custom instructions can implement the `InstructionExecutor` trait for a more structured approach.
//! - The emulator prevents overwriting existing standard RISC-V instructions to maintain compatibility.
//!

use std::collections::{btree_map, hash_map, BTreeMap, HashMap};
use std::sync::RwLock;

use super::instructions::{InstructionExecutorFn, INSTRUCTION_EXECUTOR};
use crate::{
    cpu::Cpu,
    elf::{ElfFile, WORD_SIZE},
    error::{Result, VMError},
    memory::Memory,
    riscv::{decode_until_end_of_a_block, BasicBlock, Instruction, Opcode},
};

#[derive(Debug)]
pub struct Emulator {
    // The CPU
    pub cpu: Cpu,

    // The instruction memory image
    instruction_memory: Vec<u32>,

    // Instruction Executor
    instruction_executor: &'static RwLock<HashMap<Opcode, InstructionExecutorFn>>,

    // The writable memory image
    pub data_memory: Memory,

    // The global clock counter
    global_clock: usize,

    // Basic block cache to improve performance
    basic_block_cache: BTreeMap<u32, BasicBlock>,

    // The base address of the program
    base_address: u32,

    // The entrypoint of the program
    entrypoint: u32,
}

impl Default for Emulator {
    fn default() -> Self {
        Self {
            cpu: Cpu::default(),
            instruction_memory: Vec::new(),
            instruction_executor: &INSTRUCTION_EXECUTOR,
            data_memory: Memory::default(),
            global_clock: 0,
            basic_block_cache: BTreeMap::default(),
            base_address: 0,
            entrypoint: 0,
        }
    }
}

impl Emulator {
    pub fn from_elf(elf: ElfFile) -> Self {
        // We assume the compiler will make sure that there is no execution code
        // in the readonly memory region, thus, we simplify the memory model by
        // concatenating the rom_image and ram_image into a single memory image.
        let mut combined_memory = elf.ram_image;
        combined_memory.extend(elf.rom_image);
        let mut emulator = Self {
            instruction_memory: elf.instructions,
            data_memory: Memory::from(combined_memory),
            base_address: elf.base,
            entrypoint: elf.entry,
            ..Default::default()
        };
        emulator.cpu.pc.value = emulator.entrypoint;
        emulator
    }

    /// Executes a single RISC-V instruction.
    ///
    /// 1. Retrieves the instruction executor function for the given opcode via HashMap.
    /// 2. Executes the instruction using the appropriate executor function.
    /// 3. Updates the program counter (PC) if the instruction is not a branch or jump.
    /// 4. Increments the global clock.
    fn execute_instruction(&mut self, bare_instruction: &Instruction) -> Result<()> {
        if let Some(executor) = self
            .instruction_executor
            .read()
            .map_err(|e| VMError::InstructionExecutorLockError(e.to_string()))?
            .get(&bare_instruction.opcode)
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
            let block = decode_until_end_of_a_block(&self.instruction_memory[address as usize..]);
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
    ///
    /// This method allows extending the emulator's instruction set by adding custom opcodes
    /// and their execution logic.
    /// This will return a new emulator with the added opcode.
    pub fn add_opcode(self, opcode: Opcode, function: InstructionExecutorFn) -> Result<Self> {
        let mut map = self
            .instruction_executor
            .write()
            .map_err(|e| VMError::InstructionExecutorLockError(e.to_string()))?;

        match map.entry(opcode) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(function);
                Ok(self)
            }
            hash_map::Entry::Occupied(_) => Err(VMError::DuplicateInstruction(opcode)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{InstructionExecutor, RegisterFile};
    use crate::elf::ElfFile;
    use crate::riscv::{Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_emulator_add_opcode() {
        // Add a custom opcode
        let custom_opcode = Opcode::CUSTOM0;

        let custom_function =
            |cpu: &mut Cpu, data_memory: &mut Memory, instruction: &Instruction| {
                pub struct CustomInstruction {
                    rd: (Register, u32),
                    rs1: (Register, u32),
                    rs2: (Option<Register>, u32),
                }

                impl InstructionExecutor for CustomInstruction {
                    type InstructionState = Self;
                    type Result = Result<()>;
                    fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
                        Self {
                            rd: (ins.op_a, registers[ins.op_a]),
                            rs1: (ins.op_b, registers[ins.op_b]),
                            rs2: match ins.ins_type {
                                InstructionType::RType => (
                                    Some(Register::from(ins.op_c as u8)),
                                    registers[Register::from(ins.op_c as u8)],
                                ),
                                _ => (None, ins.op_c),
                            },
                        }
                    }

                    fn memory_read(&mut self, _memory: &Memory) -> Self::Result {
                        Ok(())
                    }

                    fn execute(&mut self) {
                        self.rd.1 = (self.rs1.1 + 1) * 21 + self.rs2.1;
                    }

                    fn memory_write(&self, _memory: &mut Memory) -> Self::Result {
                        Ok(())
                    }

                    fn write_back(&self, cpu: &mut Cpu) {
                        cpu.registers.write(self.rd.0, self.rd.1);
                    }
                }
                let mut ins = CustomInstruction::decode(instruction, &cpu.registers);
                ins.memory_read(data_memory).unwrap();
                ins.execute();
                ins.memory_write(data_memory).unwrap();
                ins.write_back(cpu);
                Ok(())
            };
        let mut emulator = Emulator::default()
            .add_opcode(custom_opcode, custom_function)
            .unwrap();

        let basic_block = BasicBlock::new(vec![
            Instruction::new(Opcode::ADDI, 1, 0, 1, InstructionType::IType),
            Instruction::new(Opcode::CUSTOM0, 4, 1, 0, InstructionType::RType),
        ]);

        emulator.execute_basic_block(&basic_block).unwrap();
        assert_eq!(emulator.cpu.registers.read(Register::X4), 42);
    }

    #[test]
    fn test_emulator_add_duplicate_opcode() {
        // Opcode:ADD is already exists, so adding it again should return an error
        let custom_opcode = Opcode::ADD;
        let custom_function =
            |_cpu: &mut Cpu, _data_memory: &mut Memory, _instruction: &Instruction| Ok(());

        let emulator = Emulator::default().add_opcode(custom_opcode, custom_function);
        assert_eq!(
            emulator.unwrap_err(),
            VMError::DuplicateInstruction(Opcode::ADD)
        );
    }

    #[test]
    fn test_emulate_instructions() {
        let elf_file = ElfFile::from_path("test/hello.elf").expect("Unable to load ELF file");
        let mut emulator = Emulator::from_elf(elf_file);

        assert_eq!(emulator.execute(), Err(VMError::VMStopped))
    }

    #[test]
    #[rustfmt::skip]
    fn test_fibonacci() {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new(Opcode::ADDI, 1, 0, 1, InstructionType::IType),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new(Opcode::ADD, 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::ADD, 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::ADD, 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::ADD, 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::ADD, 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::ADD, 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::ADD, 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::ADD, 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::ADD, 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::ADD, 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::ADD, 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::ADD, 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::ADD, 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::ADD, 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::ADD, 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::ADD, 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::ADD, 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::ADD, 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::ADD, 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::ADD, 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::ADD, 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::ADD, 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::ADD, 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::ADD, 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::ADD, 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::ADD, 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::ADD, 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::ADD, 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::ADD, 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::ADD, 31, 30, 29, InstructionType::RType),
        ]);

        let mut emulator = Emulator::default();
        emulator.execute_basic_block(&basic_block).unwrap();

        assert_eq!(emulator.cpu.registers[31.into()], 1346269);
    }
}
