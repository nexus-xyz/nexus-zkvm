//! Represents the Central Processing Unit (CPU) of the RISC-V emulator.
//!
//! This struct contains all the essential components and state information
//! needed to emulate a RISC-V processor.

use super::registerfile::{RegisterFile, PC};
use crate::error::Result;
use crate::memory::MemoryProcessor;
use crate::riscv::Instruction;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    /// The general purpose 32-bit registers.
    pub registers: RegisterFile,

    /// The current program counter (PC).
    pub pc: PC,

    /// The cycle counter.
    pub cycles: u64,

    /// A snapshot of the CPU state at the beginning of the current block.
    pub snapshot: (RegisterFile, PC),
}

pub trait InstructionState {
    type Result;

    /// Executes the instruction's operation.
    ///
    /// This method performs the actual operation specified by the instruction,
    /// such as arithmetic, logical operations, or control flow changes.
    /// * `self` - The current instruction state.
    fn execute(&mut self);

    /// Performs memory access for load operations.
    ///
    /// # Arguments
    /// * `self` - The mutable current instruction state.
    /// * `memory` - Immutable reference to the memory subsystem.
    ///
    /// # Returns
    /// A `Result` indicating the outcome of the memory access operation.
    fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<Self::Result>;

    /// Performs memory access for store operations.
    ///
    /// # Arguments
    /// * `self` - The immutable current instruction state.
    /// * `memory` - Mutable reference to the memory subsystem.
    ///
    /// # Returns
    /// A `Result` indicating the outcome of the memory access operation.
    fn memory_write(&self, memory: &mut impl MemoryProcessor) -> Result<Self::Result>;

    /// Updates the CPU state with the result of the instruction execution.
    ///
    /// This method writes back the results to registers or updates other CPU state as necessary.
    ///
    /// # Arguments
    /// * `self` - The current instruction state.
    /// * `cpu` - Mutable reference to the CPU state.
    fn write_back(&self, cpu: &mut Cpu);
}

/// Trait defining the execution stages of a RISC-V instruction.
///
/// This trait represents a simplified instruction cycle, excluding the fetch stage.
/// It includes decode, execute, memory access, and write-back stages.
pub trait InstructionExecutor {
    type InstructionState: InstructionState;

    /// Decodes the instruction and prepares operands.
    ///
    /// # Arguments
    /// * `ins` - The instruction to be decoded.
    /// * `regs` - The current state of the CPU registers.
    ///
    /// # Returns
    /// An `InstructionState` containing the decoded instruction information.
    fn decode(ins: &Instruction, regs: &RegisterFile) -> Self::InstructionState;

    /// Evaluates the constructed executor
    ///
    /// # Arguments
    /// * `cpu` - Mutable reference to the CPU state.
    /// * `memory` - Immutable reference to the memory subsystem.
    /// * `ins` - The instruction to be decoded.
    ///
    /// # Returns
    /// A `Result` indicating the whether the instruction was executed successfully.
    fn evaluator<M: MemoryProcessor>(
        cpu: &mut Cpu,
        memory: &mut M,
        ins: &Instruction,
    ) -> Result<()> {
        let mut executor: Self::InstructionState = Self::decode(ins, &cpu.registers);
        executor.memory_read(memory)?;
        executor.execute();
        executor.memory_write(memory)?;
        executor.write_back(cpu);
        Ok(())
    }
}
