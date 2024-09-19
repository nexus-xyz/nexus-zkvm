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

pub struct DivInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(DivInstruction, |a: u32, b: u32| {
    let a = a as i32;
    let b = b as i32;
    let c = if b == 0 {
        -1
    } else if a == i32::MIN && b == -1 {
        i32::MIN
    } else {
        a.wrapping_div(b)
    };
    c as u32
});

pub struct DivuInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(DivuInstruction, |a: u32, b: u32| {
    if b == 0 {
        u32::MAX
    } else {
        a.wrapping_div(b)
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_div_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(Opcode::DIV, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 6);
    }

    #[test]
    fn test_div_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-20i32) as u32);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(Opcode::DIV, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), (-6i32) as u32);
    }

    #[test]
    fn test_div_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(Opcode::DIV, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), (-1i32) as u32);
    }

    #[test]
    fn test_div_overflow() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, i32::MIN as u32);
        cpu.registers.write(Register::X2, (-1i32) as u32);

        let bare_instruction = Instruction::new(Opcode::DIV, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), i32::MIN as u32);
    }

    #[test]
    fn test_divu_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(Opcode::DIVU, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 6);
    }

    #[test]
    fn test_divu_large_numbers() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new(Opcode::DIVU, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0x7FFFFFFF);
    }

    #[test]
    fn test_divu_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(Opcode::DIVU, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), u32::MAX);
    }

    #[test]
    fn test_divu_max_value() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, u32::MAX);

        let bare_instruction = Instruction::new(Opcode::DIVU, 3, 1, 2, InstructionType::RType);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 1);
    }
}
