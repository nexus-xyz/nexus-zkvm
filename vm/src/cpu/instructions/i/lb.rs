use crate::{
    cpu::{
        instructions::macros::implement_load_instruction,
        state::{InstructionExecutor, InstructionState},
    },
    memory::{MemAccessSize, MemoryProcessor},
    riscv::{Instruction, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct LbInstruction {
    rd: (Register, u32),
    rs1: u32,
    imm: u32,
}

implement_load_instruction!(LbInstruction, MemAccessSize::Byte, true, u8);

pub struct LbuInstruction {
    rd: (Register, u32),
    rs1: u32,
    imm: u32,
}

implement_load_instruction!(LbuInstruction, MemAccessSize::Byte, false, u8);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::memory::VariableMemory;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    fn setup_memory() -> VariableMemory {
        let mut memory = VariableMemory::default();
        memory.write(0x1000, MemAccessSize::Byte, 0xFF).unwrap();
        memory.write(0x1001, MemAccessSize::Byte, 0x80).unwrap();
        memory.write(0x1002, MemAccessSize::Byte, 0x7F).unwrap();
        memory.write(0x1003, MemAccessSize::Byte, 0x00).unwrap();
        memory
    }

    #[test]
    fn test_lb_positive_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LB),
            2,
            1,
            2,
            InstructionType::IType,
        );
        let mut instruction = LbInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x0000007F);
    }

    #[test]
    fn test_lb_negative_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LB),
            2,
            1,
            1,
            InstructionType::IType,
        );
        let mut instruction = LbInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0xFFFFFF80); // Sign-extended -128
    }

    #[test]
    fn test_lb_max_negative_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LB),
            2,
            1,
            0,
            InstructionType::IType,
        );
        let mut instruction = LbInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0xFFFFFFFF); // Sign-extended -1
    }

    #[test]
    fn test_lbu_positive_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LBU),
            2,
            1,
            2,
            InstructionType::IType,
        );
        let mut instruction = LbuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x0000007F);
    }

    #[test]
    fn test_lbu_negative_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LBU),
            2,
            1,
            1,
            InstructionType::IType,
        );
        let mut instruction = LbuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0x80); // Sign-extended -128
    }

    #[test]
    fn test_lbu_max_negative_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LBU),
            2,
            1,
            0,
            InstructionType::IType,
        );
        let mut instruction = LbuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X2), 0xFF); // Sign-extended -1
    }
}
