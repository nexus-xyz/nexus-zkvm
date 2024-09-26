use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor, InstructionState},
    },
    error::Result,
    memory::MemoryProcessor,
    riscv::{Instruction, InstructionType, Register},
};

pub struct MulInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(
    MulInstruction,
    |a: u32, b: u32| (a as i32).wrapping_mul(b as i32) as u32
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_mul_positive_numbers() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 5);
        cpu.registers.write(Register::X2, 7);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MUL),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 35);
    }

    #[test]
    fn test_mul_negative_numbers() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xFFFFFFFB); // -5 in two's complement
        cpu.registers.write(Register::X2, 0xFFFFFFF9); // -7 in two's complement

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MUL),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 35);
    }

    #[test]
    fn test_mul_positive_and_negative() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, (!2u32).wrapping_add(1)); // -2 in two's complement

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MUL),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), (!20u32).wrapping_add(1)); // -20 in two's complement
    }

    #[test]
    fn test_mul_overflow() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x80000000); // -2^31
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MUL),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0); // Overflow, result should be truncated
    }

    #[test]
    fn test_mul_by_zero() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MUL),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_mul_large_numbers() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x7FFFFFFF); // 2^31 - 1
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MUL),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFE); // Truncated result
    }
}
