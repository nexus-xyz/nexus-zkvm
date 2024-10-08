use crate::{
    cpu::{
        instructions::macros::implement_load_instruction,
        state::{InstructionExecutor, InstructionState},
    },
    memory::{MemAccessSize, MemoryProcessor},
    riscv::{Instruction, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct LhInstruction {
    rd: (Register, u32),
    rs1: u32,
    imm: u32,
}

implement_load_instruction!(LhInstruction, MemAccessSize::HalfWord, true, u16);

pub struct LhuInstruction {
    rd: (Register, u32),
    rs1: u32,
    imm: u32,
}

implement_load_instruction!(LhuInstruction, MemAccessSize::HalfWord, false, u16);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::memory::VariableMemory;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    fn setup_memory() -> VariableMemory {
        let mut memory = VariableMemory::default();
        // Set up some test values in memory
        memory
            .write(0x1000, MemAccessSize::HalfWord, 0xFFFF)
            .unwrap();
        memory
            .write(0x1002, MemAccessSize::HalfWord, 0x8000)
            .unwrap();
        memory
            .write(0x1004, MemAccessSize::HalfWord, 0x7FFF)
            .unwrap();
        memory
            .write(0x1006, MemAccessSize::HalfWord, 0x0000)
            .unwrap();
        memory
    }

    #[test]
    fn test_lh_positive_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LH),
            2,
            1,
            4,
            InstructionType::IType,
        );
        let mut instruction = LhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x00007FFF);
    }

    #[test]
    fn test_lh_negative_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LH),
            2,
            1,
            2,
            InstructionType::IType,
        );
        let mut instruction = LhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0xFFFF8000); // Sign-extended -32768
    }

    #[test]
    fn test_lh_max_negative_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LH),
            2,
            1,
            0,
            InstructionType::IType,
        );
        let mut instruction = LhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0xFFFFFFFF); // Sign-extended -1
    }

    #[test]
    fn test_lhu_positive_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LHU),
            2,
            1,
            4,
            InstructionType::IType,
        );
        let mut instruction = LhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x00007FFF);
    }

    #[test]
    fn test_lhu_high_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LHU),
            2,
            1,
            2,
            InstructionType::IType,
        );
        let mut instruction = LhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x00008000); // 32768 when treated as unsigned
    }

    #[test]
    fn test_lhu_max_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LHU),
            2,
            1,
            0,
            InstructionType::IType,
        );
        let mut instruction = LhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x0000FFFF);
    }

    #[test]
    fn test_lh_lhu_zero() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        // Test LH
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LH),
            2,
            1,
            6,
            InstructionType::IType,
        );
        let mut instruction = LhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x00000000);

        // Test LHU
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LHU),
            3,
            1,
            6,
            InstructionType::IType,
        );
        let mut instruction = LhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0x00000000);
    }

    #[test]
    fn test_lh_lhu_address_overflow() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, u32::MAX);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LH),
            2,
            1,
            1,
            InstructionType::IType,
        );
        let mut instruction = LhInstruction::decode(&bare_instruction, &cpu.registers);

        assert!(instruction.memory_read(&memory).is_err());

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LHU),
            2,
            1,
            1,
            InstructionType::IType,
        );
        let mut instruction = LhuInstruction::decode(&bare_instruction, &cpu.registers);

        assert!(instruction.memory_read(&memory).is_err());
    }
}
