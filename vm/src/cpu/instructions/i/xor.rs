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

pub struct XorInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(XorInstruction, |a: u32, b: u32| a ^ b);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{Instruction, Opcode, Register};

    #[test]
    fn test_xor_basic() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0b1010);
        cpu.registers.write(Register::X2, 0b1100);

        let bare_instruction = Instruction::new(Opcode::XOR, 3, 1, 2, InstructionType::RType);

        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the xor instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check the result (1010 ^ 1100 = 0110)
        assert_eq!(cpu.registers.read(Register::X3), 0b0110);
    }

    #[test]
    fn test_xor_with_zero() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xABCDEF12);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(Opcode::XOR, 3, 1, 2, InstructionType::RType);

        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // XOR with 0 should not change the value
        assert_eq!(cpu.registers.read(Register::X3), 0xABCDEF12);
    }

    #[test]
    fn test_xor_with_all_ones() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xABCDEF12);
        cpu.registers.write(Register::X2, 0xFFFFFFFF);

        let bare_instruction = Instruction::new(Opcode::XOR, 3, 1, 2, InstructionType::RType);

        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // XOR with all 1's should flip all bits
        assert_eq!(cpu.registers.read(Register::X3), 0x543210ED);
    }

    #[test]
    fn test_xor_same_register() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xAA55AA55);

        let bare_instruction = Instruction::new(Opcode::XOR, 1, 1, 1, InstructionType::RType);

        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // XOR with itself should always result in 0
        assert_eq!(cpu.registers.read(Register::X1), 0);
    }

    #[test]
    fn test_xor_alternating_bits() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xAAAAAAAA);
        cpu.registers.write(Register::X2, 0x55555555);

        let bare_instruction = Instruction::new(Opcode::XOR, 3, 1, 2, InstructionType::RType);

        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // XOR of alternating bit patterns should result in all 1's
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFF);
    }

    #[test]
    fn test_xor_idempotent() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xABCDEF12);
        cpu.registers.write(Register::X2, 0x12345678);

        let bare_instruction = Instruction::new(Opcode::XOR, 3, 1, 2, InstructionType::RType);

        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        let result1 = cpu.registers.read(Register::X3);

        // XOR the result again with the second operand
        cpu.registers.write(Register::X1, result1);
        let mut instruction = XorInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // The result should be the same as the first operand
        assert_eq!(cpu.registers.read(Register::X3), 0xABCDEF12);
    }
}
