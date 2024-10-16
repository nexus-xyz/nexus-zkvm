use crate::memory::{LoadOps, StoreOps};
use crate::{error::MemoryError, memory::MemoryProcessor, riscv::instruction::Instruction};

use super::{pc::PC, registers::Registers};

pub type InstructionResult = Option<u32>;

/// Interface that a CPU implementation must provide.
pub trait Processor {
    /// Returns an immutable reference to the CPU registers.
    fn registers(&self) -> &impl Registers;

    /// Returns a mutable reference to the CPU registers.
    fn registers_mut(&mut self) -> &mut impl Registers;

    fn pc(&self) -> &PC;

    fn pc_mut(&mut self) -> &mut PC;
}

pub trait InstructionState {
    /// Convenience function for easily implementing `memory_read` for readless instructions.
    fn readless() -> Result<LoadOps, MemoryError> {
        Ok(LoadOps::default())
    }

    /// Convenience function for easily implementing `memory_write` for writeless instructions.
    fn writeless() -> Result<StoreOps, MemoryError> {
        Ok(StoreOps::default())
    }

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
    fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<LoadOps, MemoryError>;

    /// Performs memory access for store operations.
    ///
    /// # Arguments
    /// * `self` - The immutable current instruction state.
    /// * `memory` - Mutable reference to the memory subsystem.
    ///
    /// # Returns
    /// A `Result` indicating the outcome of the memory access operation.
    fn memory_write(&self, memory: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError>;

    /// Updates the CPU state with the result of the instruction execution.
    ///
    /// This method writes back the results to registers or updates other CPU state as necessary.
    ///
    /// # Arguments
    /// * `self` - The current instruction state.
    /// * `cpu` - Mutable reference to the CPU state.
    ///
    /// # Returns
    /// An `Option<u32>` containing the result of the instruction execution, if any.
    ///
    /// This result is intended to simplify the vm <-> prover interface, by not requiring
    /// the prover to find or reconstruct it from the registers or memory operations in
    /// order to incorporate it into the witness.
    fn write_back(&self, cpu: &mut impl Processor) -> InstructionResult;
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
    fn decode(ins: &Instruction, regs: &impl Registers) -> Self::InstructionState;

    /// Evaluates the constructed executor
    ///
    /// # Arguments
    /// * `cpu` - Mutable reference to the CPU state.
    /// * `memory` - Immutable reference to the memory subsystem.
    /// * `ins` - The instruction to be decoded.
    ///
    /// # Returns
    /// A `Result` indicating the whether the instruction was executed successfully, and
    /// containing the instruction result and load/store operations that occurred.
    fn evaluator(
        cpu: &mut impl Processor,
        memory: &mut impl MemoryProcessor,
        ins: &Instruction,
    ) -> Result<(InstructionResult, (LoadOps, StoreOps)), MemoryError> {
        let mut executor: Self::InstructionState = Self::decode(ins, cpu.registers());

        let load_ops = executor.memory_read(memory)?;
        executor.execute();
        let store_ops = executor.memory_write(memory)?;

        let res = executor.write_back(cpu);

        Ok((res, (load_ops, store_ops)))
    }
}
