use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor},
    },
    error::Result,
    memory::Memory,
    riscv::{Instruction, InstructionType, Register},
};

pub struct SubInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(SubInstruction, |a: u32, b: u32| a.wrapping_sub(b));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{Instruction, Opcode, Register};

    #[test]
    fn test_sub_instruction() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 50);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(Opcode::SUB, 3, 1, 2, InstructionType::RType);

        let mut instruction = SubInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the add instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check the result
        assert_eq!(cpu.registers.read(Register::X3), 30);
    }

    #[test]
    fn test_sub_underflow() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(Opcode::SUB, 3, 1, 2, InstructionType::RType);

        let mut instruction = SubInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the sub instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check the result (should wrap around to u32::MAX)
        assert_eq!(cpu.registers.read(Register::X3), u32::MAX);
    }
}
