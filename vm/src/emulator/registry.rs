//! # Instruction Executor Registry
//!
//! This module defines the instruction execution functionality for the RISC-V emulator.
//! It provides a centralized mapping of opcodes to their corresponding execution functions.
//!
//! ## Key Components
//!
//! - `InstructionExecutorFn`: A type alias for the instruction execution function signature.
//! - `InstructionExecutorRegistry`: A struct containing mappings of opcodes to their execution functions.
//!
//! ## Instruction Categories
//!
//! The registry includes various RISC-V instruction categories:
//!
//! - Arithmetic and Logical Operations (ADD, SUB, AND, OR, XOR, etc.)
//! - Shift Operations (SLL, SRL, SRA)
//! - Comparison Operations (SLT, SLTU)
//! - Multiplication and Division Operations (MUL, DIV, REM, etc.)
//! - Memory Operations (LB, LH, LW, SB, SH, SW, etc.)
//! - Control Flow Operations (JAL, JALR, BEQ, BNE, etc.)
//! - Upper Immediate Operations (LUI, AUIPC)
//!
//! ## Special Instructions
//!
//! The registry includes special handling for read input (`rin`) and write output (`wou`) instructions:
//!
//! - `rin` is interpreted as `lw` (load word)
//! - `wou` is interpreted as `sw` (store word)
//!
//! ## Error Handling
//!
//! The registry provides error handling for:
//! - Duplicate instructions
//! - Unimplemented instructions
//! - Undefined instructions
//!
//! ## Performance Considerations
//!
//! - Built-in instructions use a static array for fast lookup.
//! - Custom instructions use a `HashMap` for flexible extension.
//! - Special instructions (`rin` and `wou`) have dedicated fast-path checks.
//!
//! ## Implementation Details
//!
//! - The `InstructionExecutorRegistry` struct contains:
//!   - A static array `builtins` for built-in RISC-V instructions.
//!   - A `HashMap` `precompiles` for custom instructions.
//!   - Special `Opcode`s for read input and write output operations.
//! - The `add_opcode` method allows adding custom instructions at runtime.
//! - The `get` method retrieves the execution function for a given opcode.
//! - Special methods `get_for_read_input` and `get_for_write_output` handle the custom I/O instructions.
//!
//! This registry is crucial for the emulator's operation, providing a flexible and
//! efficient way to map opcodes to their execution functions, including support for
//! custom and special instructions.
use nexus_common::{constants::KECCAKF_OPCODE, cpu::InstructionExecutor, error::MemoryError};

use crate::error::{VMError, VMErrorKind};
use crate::memory::MemoryProcessor;
use crate::{
    cpu::{instructions, Cpu},
    error::Result,
    memory::{LoadOps, StoreOps, UnifiedMemory},
    riscv::{BuiltinOpcode, Instruction, Opcode},
};
use std::collections::{hash_map::Entry, HashMap};

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
    keccakf: Opcode,
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
                    instructions::SrlInstruction::evaluator
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
            keccakf: Opcode::new(KECCAKF_OPCODE, Some(0b000), None, "keccakf"),
        }
    }
}

impl InstructionExecutorRegistry {
    pub fn add_opcode<IE: InstructionExecutor>(&mut self, op: &Opcode) -> Result<(), VMError> {
        match self.precompiles.entry(op.clone()) {
            Entry::Occupied(_) => Err(VMErrorKind::DuplicateInstruction(op.clone()).into()),
            Entry::Vacant(v) => {
                v.insert(register_instruction_executor!(IE::evaluator));
                Ok(())
            }
        }
    }

    pub fn get(&self, op: &Opcode) -> Result<InstructionExecutorFn<UnifiedMemory>> {
        if let Ok(opcode) = TryInto::<BuiltinOpcode>::try_into(op.clone()) {
            let idx = opcode as usize;

            // Safety: the length of `builtins` is statically guaranteed to be equal to the number
            // of variants in `BuiltinOpcode`.
            #[allow(clippy::unnecessary_lazy_evaluations)]
            self.builtins[idx]
                .ok_or_else(|| VMErrorKind::UnimplementedInstruction(op.clone()).into())
        } else {
            if let Some(func) = self.precompiles.get(op) {
                return Ok(*func);
            }

            Err(VMErrorKind::UndefinedInstruction(op.clone()).into())
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

    pub fn custom_executor_from_opcode<M: MemoryProcessor>(
        &self,
        op: &Opcode,
    ) -> Option<InstructionExecutorFn<M>> {
        Some(match op {
            op if self.is_keccakf(op) => {
                instructions::custom::keccakf::KeccakFInstruction::evaluator
                    as InstructionExecutorFn<M>
            }
            _ => return None,
        })
    }

    #[inline(always)]
    pub fn is_read_input(&self, op: &Opcode) -> bool {
        op.raw() == self.read_input.raw() && op.fn3() == self.read_input.fn3()
    }

    #[inline(always)]
    pub fn is_write_output(&self, op: &Opcode) -> bool {
        op.raw() == self.write_output.raw() && op.fn3() == self.write_output.fn3()
    }

    #[inline(always)]
    pub fn is_keccakf(&self, op: &Opcode) -> bool {
        op.raw() == self.keccakf.raw() && op.fn3() == self.keccakf.fn3()
    }
}
