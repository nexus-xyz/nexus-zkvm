# Adding a New Instruction to RISC-V 32IM to CPU

## Overview

This guide explains how to add a new instruction to RISC-V 32IM CPU.


Any instruction in the CPU is abstracted via Trait `InstructionExecutor`.

```rust

/// Trait defining the execution stages of a RISC-V instruction.
pub trait InstructionExecutor {
    /// Represents the intermediate state of an instruction during execution.
    type InstructionState;
    type Result;

    fn decode(ins: Instruction, regs: &RegisterFile) -> Self::InstructionState;

    /// Executes the instruction's operation.
    fn execute(&mut self);

    /// Performs memory access for load operations.
    fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<Self::Result>;

    /// Performs memory access for store operations.
    fn memory_write(&self, memory: &mut impl MemoryProcessor) -> Result<Self::Result>;

    /// Updates the CPU state with the result of the instruction execution.
    fn write_back(&self, cpu: &mut Cpu);
}
```

For example, a new instruction can perform all 5 steps above, or at least a `decode()` and one of `execute()`, `memory_read()`, `memory_write()`, `write_back()`.

## Example: Adding f(x) = a * x + b

Let's add a new instruction that computes f(x) = a * x + b, where x is a private input.

### 1. Define the new instruction struct

The instruction `f(x) = a * x + b` can be represented as `rd = rs1 * x + rs2`, we assume the instruction type is `InstructionType::RType`.

```rust
pub struct NewInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
    // We assume the address of secret is in the Register X11
    secret_addr: u32,
    secret_data: u32,
}
```

### 2. Implement the `InstructionExecutor` trait for the new instruction

The CPU must realize the behavior of the new instruction, which can be described by implement the `InstructionExecutor` trait for the new instruction.

```rust
impl InstructionExecutor for NewInstruction {
    type InstructionState = Self;
    type Result = ();

    fn decode(ins: Instruction, registers: &RegisterFile) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: registers[ins.op_c],
            secret_addr: registers[Register::X11],
        }
    }

    fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<Self::Result> {
        // Read the secret from memory
        self.secret_data = memory.read_data(self.secret_addr, MemAccessSize::Word)?;
    }

    fn execute(&mut self) {
        // Compute f(x) = rs1 * x + rs2
        // We assume x is a secret and in the Register X11
        self.rd.1 = self.rs1 * self.secret_data + self.rs2;

        // Now we want to update the secret data every time it is used.
        self.secret_data = self.secret_data.wrapping_add(0xCAFEBABE);
    }

    fn memory_write(&self, memory: &mut impl MemoryProcessor) -> Result<Self::Result> {
        // Write the updated secret data back to memory
        memory.write_data(self.secret_addr, MemAccessSize::Word, self.secret_data)?;

        // We don't want to reveal secret via return value.
        Ok(None)
    }

    fn write_back(&self, cpu: &mut Cpu) {
        // Now let's write the result back to the register file
        cpu.registers[self.rd.0] = self.rd.1;
    }
```

Here are the steps to implement the `InstructionExecutor` trait for the new instruction:

1. `decode` function:
   - Extracts operands `(rd, rs1, rs2)` from the instruction.
   - Also reads a "secret address" from register X11.

2. `memory_read` function:
   - Reads a "secret data" from memory at the address stored in `secret_addr`.

3. `execute` function:
   - Computes a function `f(x) = rs1 * x + rs2`, where x is the secret data.
   - Stores the result in `rd`.
   - Updates the secret data.

4. `memory_write` function:
   - Writes the updated secret data back to memory.
   - Returns `Ok(None)` to avoid revealing the secret through the return value.

5. `write_back` function:
   - Writes the result (stored in rd) back to the CPU's register file.
