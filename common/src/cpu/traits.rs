use crate::{error::MemoryError, memory::MemoryProcessor, riscv::instruction::Instruction};

use super::{pc::PC, registers::Registers};

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
    fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<Self::Result, MemoryError>;

    /// Performs memory access for store operations.
    ///
    /// # Arguments
    /// * `self` - The immutable current instruction state.
    /// * `memory` - Mutable reference to the memory subsystem.
    ///
    /// # Returns
    /// A `Result` indicating the outcome of the memory access operation.
    fn memory_write(&self, memory: &mut impl MemoryProcessor) -> Result<Self::Result, MemoryError>;

    /// Updates the CPU state with the result of the instruction execution.
    ///
    /// This method writes back the results to registers or updates other CPU state as necessary.
    ///
    /// # Arguments
    /// * `self` - The current instruction state.
    /// * `cpu` - Mutable reference to the CPU state.
    fn write_back(&self, cpu: &mut impl Processor);
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
    /// A `Result` indicating the whether the instruction was executed successfully.
    fn evaluator(
        cpu: &mut impl Processor,
        memory: &mut impl MemoryProcessor,
        ins: &Instruction,
    ) -> Result<(), MemoryError> {
        let mut executor: Self::InstructionState = Self::decode(ins, cpu.registers());
        executor.memory_read(memory)?;
        executor.execute();
        executor.memory_write(memory)?;
        executor.write_back(cpu);
        Ok(())
    }
}
