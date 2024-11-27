//! # Instruction Executor Module
//!
//! This module defines the instruction execution functionality for the RISC-V emulator.
//! It provides a centralized mapping of opcodes to their corresponding execution functions.
//!
//! ## Key Components
//!
//! - `InstructionExecutorFn`: A generic type alias for the instruction execution function signature.
//! - `InstructionExecutorRegistry`: A struct containing `InstructionExecutorFn`s for use during emulation.
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
//!     memory::{MemoryProcessor, LoadOps, StoreOps},
//!     emulator::{Emulator, HarvardEmulator},
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
//!
//!     fn execute(&mut self) {
//!         self.rd.1 = 2 * self.rs1 + self.rs2;
//!     }
//!
//!     fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
//!         <CustomInstruction as InstructionState>::readless()
//!     }
//!
//!     fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
//!         <CustomInstruction as InstructionState>::writeless()
//!     }
//!
//!     fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
//!         cpu.registers_mut().write(self.rd.0, self.rd.1);
//!         Some(self.rd.1)
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
//! let custom_opcode = Opcode::new(0b1111111, None, None, "test");
//! let mut emulator = HarvardEmulator::default().add_opcode::<CustomInstruction>(&custom_opcode);
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

use crate::memory::MemoryProcessor;
use crate::{
    cpu::{instructions, Cpu},
    error::{Result, VMError},
    memory::{LoadOps, StoreOps, UnifiedMemory},
    riscv::{BuiltinOpcode, Instruction, Opcode},
};
use std::collections::HashMap;

pub type InstructionExecutorFn<M> =
    fn(&mut Cpu, &mut M, &Instruction) -> Result<(Option<u32>, (LoadOps, StoreOps)), MemoryError>;

macro_rules! register_instruction_executor {
    ($func: path) => {
        $func as InstructionExecutorFn<UnifiedMemory>
    };
}

#[derive(Debug)]
pub struct InstructionExecutorRegistry {
    builtins: [Option<InstructionExecutorFn<UnifiedMemory>>; BuiltinOpcode::VARIANT_COUNT],
    precompiles: HashMap<Opcode, InstructionExecutorFn<UnifiedMemory>>,
    read_input: Opcode,
    write_output: Opcode,
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
                None, // ecall, handled by src/system/syscall.rs instead
                None, // ebreak
                None, // fence
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
                None, // unimpl
            ],
            precompiles: HashMap::<Opcode, InstructionExecutorFn<UnifiedMemory>>::new(),
            read_input: Opcode::new(0b0101011, Some(0b000), None, "rin"),
            write_output: Opcode::new(0b1011011, Some(0b000), None, "wou"),
        }
    }
}

impl InstructionExecutorRegistry {
    pub fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<(), VMError> {
        self.precompiles
            .insert(op.clone(), register_instruction_executor!(IE::evaluator))
            .ok_or(VMError::DuplicateInstruction(op.clone()))
            .map(|_| ())
    }

    pub fn get(&self, op: &Opcode) -> Result<InstructionExecutorFn<UnifiedMemory>> {
        if let Ok(opcode) = TryInto::<BuiltinOpcode>::try_into(op.clone()) {
            let idx = opcode as usize;

            // Safety: the length of `builtins` is statically guaranteed to be equal to the number
            // of variants in `BuiltinOpcode`.
            #[allow(clippy::unnecessary_lazy_evaluations)]
            self.builtins[idx].ok_or_else(|| VMError::UnimplementedInstruction(op.clone()))
        } else {
            if let Some(func) = self.precompiles.get(op) {
                return Ok(*func);
            }

            Err(VMError::UndefinedInstruction(op.clone()))
        }
    }

    pub fn get_for_read_input<M: MemoryProcessor>(
        &self,
        op: &Opcode,
    ) -> Option<InstructionExecutorFn<M>> {
        // Opcode will be parsed dynamically so the name will be different.
        if self.is_read_input(op) {
            // Interpret `rin` as `lw`.
            return Some(instructions::LwInstruction::evaluator as InstructionExecutorFn<M>);
        }

        None
    }

    pub fn get_for_write_output<M: MemoryProcessor>(
        &self,
        op: &Opcode,
    ) -> Option<InstructionExecutorFn<M>> {
        // Opcode will be parsed dynamically so the name will be different.
        if self.is_write_output(op) {
            // Interpret `wou` as `sw`.
            return Some(instructions::SwInstruction::evaluator as InstructionExecutorFn<M>);
        }

        None
    }

    #[inline(always)]
    pub fn is_read_input(&self, op: &Opcode) -> bool {
        op.raw() == self.read_input.raw() && op.fn3() == self.read_input.fn3()
    }

    #[inline(always)]
    pub fn is_write_output(&self, op: &Opcode) -> bool {
        op.raw() == self.write_output.raw() && op.fn3() == self.write_output.fn3()
    }
}
