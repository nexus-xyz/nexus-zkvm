use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::MemoryProcessor,
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct AddInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(AddInstruction, |a: u32, b: u32| a.wrapping_add(b));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_add_instruction() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::ADD),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = AddInstruction::decode(&bare_instruction, &cpu.registers);
        // Execute the add instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check the result
        assert_eq!(cpu.registers.read(Register::X3), 30);
    }

    #[test]
    fn test_add_overflow() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::ADD),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = AddInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the add instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check the result (should wrap around to 0)
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }
}
