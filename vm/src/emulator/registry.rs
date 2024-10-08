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
//!     cpu::{Cpu, RegisterFile},
//!     memory::MemoryProcessor,
//!     emulator::Emulator,
//!     riscv::{Register, Opcode, Instruction, InstructionType},
//!     error::Result
//! };
//! use nexus_common::cpu::{InstructionState, InstructionExecutor, Processor, Registers};
//! use nexus_common::error::MemoryError;
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
//!     fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<Self::Result, MemoryError> {
//!         Ok(None)
//!     }
//!
//!     fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<Self::Result, MemoryError> {
//!         Ok(None)
//!     }
//!
//!     fn write_back(&self, cpu: &mut impl Processor) {
//!         cpu.registers_mut().write(self.rd.0, self.rd.1);
//!     }
//! }
//!
//! impl InstructionExecutor for CustomInstruction {
//!     type InstructionState = Self;
//!
//!     fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
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

use nexus_common::{cpu::InstructionExecutor, error::MemoryError};

use crate::{
    cpu::{instructions, Cpu},
    error::{Result, VMError},
    memory::{FixedMemory, MemoryProcessor, VariableMemory},
    riscv::{BuiltinOpcode, Instruction, Opcode},
};
use std::collections::HashMap;

pub type InstructionExecutorFn<M> = fn(&mut Cpu, &mut M, &Instruction) -> Result<(), MemoryError>;

fn nop<M: MemoryProcessor>(
    _cpu: &mut Cpu,
    _memory: &mut M,
    _ins: &Instruction,
) -> Result<(), MemoryError> {
    Ok(())
}

fn ecall<M: MemoryProcessor>(
    _cpu: &mut Cpu,
    _memory: &mut M,
    _ins: &Instruction,
) -> Result<(), MemoryError> {
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
    builtins: [Option<InstructionExecutorFns>; BuiltinOpcode::VARIANT_COUNT],
    precompiles: HashMap<Opcode, InstructionExecutorFns>,
}

impl Default for InstructionExecutorRegistry {
    fn default() -> Self {
        Self {
            builtins: [
                // nb: must have same ordering as Opcode enum
                Some(register_instruction_executor!(
                    instructions::AddInstruction::evaluator
                )), // add
                Some(register_instruction_executor!(
                    instructions::SubInstruction::evaluator
                )), // sub
                Some(register_instruction_executor!(
                    instructions::SllInstruction::evaluator
                )), // sll
                Some(register_instruction_executor!(
                    instructions::SltInstruction::evaluator
                )), // slt
                Some(register_instruction_executor!(
                    instructions::SltuInstruction::evaluator
                )), // sltu
                Some(register_instruction_executor!(
                    instructions::XorInstruction::evaluator
                )), // xor
                Some(register_instruction_executor!(
                    instructions::SraInstruction::evaluator
                )), // srl
                Some(register_instruction_executor!(
                    instructions::SraInstruction::evaluator
                )), // sra
                Some(register_instruction_executor!(
                    instructions::OrInstruction::evaluator
                )), // or
                Some(register_instruction_executor!(
                    instructions::AndInstruction::evaluator
                )), // and
                Some(register_instruction_executor!(
                    instructions::MulInstruction::evaluator
                )), // mul
                Some(register_instruction_executor!(
                    instructions::MulhInstruction::evaluator
                )), // mulh
                Some(register_instruction_executor!(
                    instructions::MulhsuInstruction::evaluator
                )), // mulhsu
                Some(register_instruction_executor!(
                    instructions::MulhuInstruction::evaluator
                )), // mulhu
                Some(register_instruction_executor!(
                    instructions::DivInstruction::evaluator
                )), // div
                Some(register_instruction_executor!(
                    instructions::DivuInstruction::evaluator
                )), // divu
                Some(register_instruction_executor!(
                    instructions::RemInstruction::evaluator
                )), // rem
                Some(register_instruction_executor!(
                    instructions::RemuInstruction::evaluator
                )), // remu
                Some(register_instruction_executor!(
                    instructions::AddInstruction::evaluator
                )), // addi
                Some(register_instruction_executor!(
                    instructions::SllInstruction::evaluator
                )), // slli
                Some(register_instruction_executor!(
                    instructions::SltInstruction::evaluator
                )), // slti
                Some(register_instruction_executor!(
                    instructions::SltuInstruction::evaluator
                )), // sltiu
                Some(register_instruction_executor!(
                    instructions::XorInstruction::evaluator
                )), // xori
                Some(register_instruction_executor!(
                    instructions::SrlInstruction::evaluator
                )), // srli
                Some(register_instruction_executor!(
                    instructions::SraInstruction::evaluator
                )), // srai
                Some(register_instruction_executor!(
                    instructions::OrInstruction::evaluator
                )), // ori
                Some(register_instruction_executor!(
                    instructions::AndInstruction::evaluator
                )), // andi
                Some(register_instruction_executor!(
                    instructions::LbInstruction::evaluator
                )), // lb
                Some(register_instruction_executor!(
                    instructions::LhInstruction::evaluator
                )), // lh
                Some(register_instruction_executor!(
                    instructions::LwInstruction::evaluator
                )), // lw
                Some(register_instruction_executor!(
                    instructions::LbuInstruction::evaluator
                )), // lbu
                Some(register_instruction_executor!(
                    instructions::LhuInstruction::evaluator
                )), // lhu
                Some(register_instruction_executor!(
                    instructions::JalrInstruction::evaluator
                )), // jalr
                Some(register_instruction_executor!(ecall)), // ecall
                None,                                        // ebreak
                None,                                        // fence
                Some(register_instruction_executor!(
                    instructions::SbInstruction::evaluator
                )), // sb
                Some(register_instruction_executor!(
                    instructions::ShInstruction::evaluator
                )), // sh
                Some(register_instruction_executor!(
                    instructions::SwInstruction::evaluator
                )), // sw
                Some(register_instruction_executor!(
                    instructions::BeqInstruction::evaluator
                )), // beq
                Some(register_instruction_executor!(
                    instructions::BneInstruction::evaluator
                )), // bne
                Some(register_instruction_executor!(
                    instructions::BltInstruction::evaluator
                )), // blt
                Some(register_instruction_executor!(
                    instructions::BgeInstruction::evaluator
                )), // bge
                Some(register_instruction_executor!(
                    instructions::BltuInstruction::evaluator
                )), // bltu
                Some(register_instruction_executor!(
                    instructions::BgeuInstruction::evaluator
                )), // bgeu
                Some(register_instruction_executor!(
                    instructions::LuiInstruction::evaluator
                )), // lui
                Some(register_instruction_executor!(
                    instructions::AuipcInstruction::evaluator
                )), // auipc
                Some(register_instruction_executor!(
                    instructions::JalInstruction::evaluator
                )), // jal
                Some(register_instruction_executor!(nop)),   // nop
                None,                                        // unimpl
            ],
            precompiles: HashMap::<Opcode, InstructionExecutorFns>::new(),
        }
    }
}

impl InstructionExecutorRegistry {
    pub fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<(), VMError> {
        self.precompiles
            .insert(*op, register_instruction_executor!(IE::evaluator))
            .ok_or(VMError::DuplicateInstruction(*op))
            .map(|_| ())
    }

    #[allow(dead_code)] // temp till second pass memory is done
    pub fn get_instruction_executor_for_fixed_memory(
        &self,
        op: &Opcode,
    ) -> Result<InstructionExecutorFn<FixedMemory>> {
        if let Ok(opcode) = TryInto::<BuiltinOpcode>::try_into(*op) {
            let idx = opcode as usize;

            // Safety: the length of `builtins` is statically guaranteed to be equal to the number
            // of variants in `BuiltinOpcode`.
            self.builtins[idx]
                .as_ref()
                .map(|fns| fns.0)
                .ok_or_else(|| VMError::UnimplementedInstruction(op.raw()))
        } else {
            if let Some(fns) = self.precompiles.get(op) {
                return Ok(fns.0);
            }

            Err(VMError::UnsupportedInstruction(op.raw()))
        }
    }

    pub fn get_instruction_executor_for_variable_memory(
        &self,
        op: &Opcode,
    ) -> Result<InstructionExecutorFn<VariableMemory>> {
        if let Ok(opcode) = TryInto::<BuiltinOpcode>::try_into(*op) {
            let idx = opcode as usize;

            // Safety: the length of `builtins` is statically guaranteed to be equal to the number
            // of variants in `BuiltinOpcode`.
            self.builtins[idx]
                .as_ref()
                .map(|fns| fns.1)
                .ok_or_else(|| VMError::UnimplementedInstruction(op.raw()))
        } else {
            if let Some(fns) = self.precompiles.get(op) {
                return Ok(fns.1);
            }

            Err(VMError::UnsupportedInstruction(op.raw()))
        }
    }
}
