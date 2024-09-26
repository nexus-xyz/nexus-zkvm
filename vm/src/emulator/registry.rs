//! # Instruction Executor Module
//!
//! This module defines the instruction execution functionality for the RISC-V emulator.
//! It provides a centralized mapping of opcodes to their corresponding execution functions.
//!
//! ## Key Components
//!
//! - `InstructionExecutorFn`: A generic type alias for the instruction execution function signature.
//! - `InstructionExecutorFns`: A tuple type of `InstructionExecutorFn`s monomorphized to specific memory models
//! - `InstructionExecutorRegistry`: A struct containing `InstructionExecutorFns` for use during emulation.
//!
//! ## Instruction Categories
//!
//! The module organizes instructions into several categories:
//!
//! - ALU Instructions: Arithmetic and logical operations
//! - Memory Instructions: Load and store operations
//! - Branch Instructions: Conditional and unconditional jumps
//! - System Instructions: Special system-level operations
//!
//! ## Extensibility
//!
//! The emulator supports adding custom opcodes and their corresponding execution functions at runtime.
//! This feature allows for extending the instruction set without modifying the core emulator code.
//!
//! To add a new opcode:
//!
//! 1. Define a new `Opcode`.
//! 2. Define a struct implementing the `InstructionExecutor` trait for that opcode.
//! 3. Use the `add_opcode` method of the `Emulator` struct to register the new opcode and its associated execution function.
//!
//! Example:
//!
//! ```rust
//! use nexus_vm::{
//!     cpu::{Cpu,
//!           RegisterFile,
//!           InstructionState,
//!           InstructionExecutor,
//!     },
//!     memory::MemoryProcessor,
//!     emulator::Emulator,
//!     riscv::{Register, Opcode, Instruction, InstructionType},
//!     error::Result
//! };
//!
//! pub struct CustomInstruction {
//!     rd: (Register, u32),
//!     rs1: u32,
//!     rs2: u32,
//! }
//!
//! impl InstructionState for CustomInstruction {
//!     type Result = Option<()>;
//!
//!     fn execute(&mut self) {
//!         self.rd.1 = 2 * self.rs1 + self.rs2;
//!     }
//!
//!     fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<Self::Result> {
//!         Ok(None)
//!     }
//!
//!     fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<Self::Result> {
//!         Ok(None)
//!     }
//!
//!     fn write_back(&self, cpu: &mut Cpu) {
//!         cpu.registers.write(self.rd.0, self.rd.1);
//!     }
//! }
//!
//! impl InstructionExecutor for CustomInstruction {
//!     type InstructionState = Self;
//!
//!     fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
//!         Self {
//!             rd: (ins.op_a, registers[ins.op_a]),
//!             rs1: registers[ins.op_b],
//!             rs2: match ins.ins_type {
//!                 InstructionType::RType => registers[Register::from(ins.op_c as u8)],
//!                 _ => ins.op_c,
//!             },
//!         }
//!     }
//! }
//!
//! let custom_opcode = Opcode::new(0b1111111, "test");
//! let mut emulator = Emulator::default().add_opcode::<CustomInstruction>(&custom_opcode);
//! ```
//!
//! Note:
//! - The `add_opcode` method checks for duplicate opcodes and returns an error if the opcode already exists.
//! - The emulator prevents overwriting existing standard RISC-V instructions to maintain compatibility.
//!
//! ## Error Handling
//!
//! Execution functions return a `Result<()>`, allowing for proper error propagation throughout the emulator.
//! The `add_opcode` method also returns a `Result`, indicating success or failure in adding the new opcode.

use crate::{
    cpu::{instructions, Cpu, InstructionExecutor},
    error::{Result, VMError},
    memory::{FixedMemory, MemoryProcessor, VariableMemory},
    riscv::{BuiltinOpcode, Instruction, Opcode},
};
use std::collections::HashMap;

pub type InstructionExecutorFn<M> = fn(&mut Cpu, &mut M, &Instruction) -> Result<()>;

fn unimpl<M: MemoryProcessor>(cpu: &mut Cpu, _memory: &mut M, _ins: &Instruction) -> Result<()> {
    Err(VMError::UnimplementedInstruction(cpu.pc.value))
}

fn nop<M: MemoryProcessor>(_cpu: &mut Cpu, _memory: &mut M, _ins: &Instruction) -> Result<()> {
    Ok(())
}

fn ecall<M: MemoryProcessor>(_cpu: &mut Cpu, _memory: &mut M, _ins: &Instruction) -> Result<()> {
    // TODO: implement syscall.rs
    Ok(())
}

// Note: The instruction executor function is generic over the memory type, but Rust requires that function pointers
//       be specifically instantiated. This functionally becomes a time-space tradeoff, where we could use dynamic
//       dispatch in order to avoid having to instantiate the executors multiple times for each memory type. However
//       we choose to pay more in terms of space (redundant compiletime instantiation) in order to have more efficient
//       execution with static dispatch, since the VM can only support 256 instructions at once anyway.
macro_rules! register_instruction_executor {
    ($func: path) => {
        InstructionExecutorFns(
            $func as InstructionExecutorFn<FixedMemory>,
            $func as InstructionExecutorFn<VariableMemory>,
        )
    };
}

#[derive(Debug)]
pub struct InstructionExecutorFns(
    pub InstructionExecutorFn<FixedMemory>,
    pub InstructionExecutorFn<VariableMemory>,
);

#[derive(Debug)]
pub struct InstructionExecutorRegistry {
    builtins: [InstructionExecutorFns; 50],
    precompiles: HashMap<Opcode, InstructionExecutorFns>,
}

impl Default for InstructionExecutorRegistry {
    fn default() -> Self {
        Self {
            builtins: [
                // nb: must have same ordering as Opcode enum
                register_instruction_executor!(instructions::AddInstruction::evaluator), // add
                register_instruction_executor!(instructions::SubInstruction::evaluator), // sub
                register_instruction_executor!(instructions::SllInstruction::evaluator), // sll
                register_instruction_executor!(instructions::SltInstruction::evaluator), // slt
                register_instruction_executor!(instructions::SltuInstruction::evaluator), // sltu
                register_instruction_executor!(instructions::XorInstruction::evaluator), // xor
                register_instruction_executor!(instructions::SraInstruction::evaluator), // srl
                register_instruction_executor!(instructions::SraInstruction::evaluator), // sra
                register_instruction_executor!(instructions::OrInstruction::evaluator),  // or
                register_instruction_executor!(instructions::AndInstruction::evaluator), // and
                register_instruction_executor!(instructions::MulInstruction::evaluator), // mul
                register_instruction_executor!(instructions::MulhInstruction::evaluator), // mulh
                register_instruction_executor!(instructions::MulhsuInstruction::evaluator), // mulhsu
                register_instruction_executor!(instructions::MulhuInstruction::evaluator),  // mulhu
                register_instruction_executor!(instructions::DivInstruction::evaluator),    // div
                register_instruction_executor!(instructions::DivuInstruction::evaluator),   // divu
                register_instruction_executor!(instructions::RemInstruction::evaluator),    // rem
                register_instruction_executor!(instructions::RemuInstruction::evaluator),   // remu
                register_instruction_executor!(instructions::AddInstruction::evaluator),    // addi
                register_instruction_executor!(instructions::SllInstruction::evaluator),    // slli
                register_instruction_executor!(instructions::SltInstruction::evaluator),    // slti
                register_instruction_executor!(instructions::SltuInstruction::evaluator),   // sltiu
                register_instruction_executor!(instructions::XorInstruction::evaluator),    // xori
                register_instruction_executor!(instructions::SrlInstruction::evaluator),    // srli
                register_instruction_executor!(instructions::SraInstruction::evaluator),    // srai
                register_instruction_executor!(instructions::OrInstruction::evaluator),     // ori
                register_instruction_executor!(instructions::AndInstruction::evaluator),    // andi
                register_instruction_executor!(instructions::LbInstruction::evaluator),     // lb
                register_instruction_executor!(instructions::LhInstruction::evaluator),     // lh
                register_instruction_executor!(instructions::LwInstruction::evaluator),     // lw
                register_instruction_executor!(instructions::LbuInstruction::evaluator),    // lbu
                register_instruction_executor!(instructions::LhuInstruction::evaluator),    // lhu
                register_instruction_executor!(instructions::JalrInstruction::evaluator),   // jalr
                register_instruction_executor!(ecall),                                      // ecall
                register_instruction_executor!(unimpl), // ebreak
                register_instruction_executor!(unimpl), // fence
                register_instruction_executor!(instructions::SbInstruction::evaluator), // sb
                register_instruction_executor!(instructions::ShInstruction::evaluator), // sh
                register_instruction_executor!(instructions::SwInstruction::evaluator), // sw
                register_instruction_executor!(instructions::BeqInstruction::evaluator), // beq
                register_instruction_executor!(instructions::BneInstruction::evaluator), // bne
                register_instruction_executor!(instructions::BltInstruction::evaluator), // blt
                register_instruction_executor!(instructions::BgeInstruction::evaluator), // bge
                register_instruction_executor!(instructions::BltuInstruction::evaluator), // bltu
                register_instruction_executor!(instructions::BgeuInstruction::evaluator), // bgeu
                register_instruction_executor!(instructions::LuiInstruction::evaluator), // lui
                register_instruction_executor!(instructions::AuipcInstruction::evaluator), // auipc
                register_instruction_executor!(instructions::JalInstruction::evaluator), // jal
                register_instruction_executor!(nop),    // nop
                register_instruction_executor!(unimpl), // unimpl
            ],
            precompiles: HashMap::<Opcode, InstructionExecutorFns>::new(),
        }
    }
}

impl InstructionExecutorRegistry {
    pub fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<()> {
        self.precompiles
            .insert(op.clone(), register_instruction_executor!(IE::evaluator))
            .ok_or(VMError::DuplicateInstruction(op.clone()))
            .map(|_| ())
    }

    #[allow(dead_code)] // temp till second pass memory is done
    pub fn into_fixed_memory(&self, op: &Opcode) -> Option<InstructionExecutorFn<FixedMemory>> {
        if let Ok(opcode) = TryInto::<BuiltinOpcode>::try_into(op.clone()) {
            let idx = opcode as usize;
            if idx > self.builtins.len() {
                return None;
            }

            Some(self.builtins[idx].0)
        } else {
            if let Some(fns) = self.precompiles.get(op) {
                return Some(fns.0);
            }

            None
        }
    }

    pub fn into_variable_memory(
        &self,
        op: &Opcode,
    ) -> Option<InstructionExecutorFn<VariableMemory>> {
        if let Ok(opcode) = TryInto::<BuiltinOpcode>::try_into(op.clone()) {
            let idx = opcode as usize;
            if idx > self.builtins.len() {
                return None;
            }

            Some(self.builtins[idx].1)
        } else {
            if let Some(fns) = self.precompiles.get(op) {
                return Some(fns.1);
            }

            None
        }
    }
}
