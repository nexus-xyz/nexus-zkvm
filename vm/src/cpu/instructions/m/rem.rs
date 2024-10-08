use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::MemoryProcessor,
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct RemInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(RemInstruction, |a: u32, b: u32| {
    let a = a as i32;
    let b = b as i32;
    if b == 0 {
        a as u32
    } else if a == i32::MIN && b == -1 {
        0
    } else {
        a.wrapping_rem(b) as u32
    }
});

pub struct RemuInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(RemuInstruction, |a: u32, b: u32| {
    if b == 0 {
        a
    } else {
        a.wrapping_rem(b)
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_rem_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REM),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // 20 % 3 = 2
        assert_eq!(cpu.registers.read(Register::X3), 2);
    }

    #[test]
    fn test_rem_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-20i32) as u32);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REM),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // -20 % 3 = -2
        // The result is negative because the dividend is negative
        assert_eq!(cpu.registers.read(Register::X3), (-2i32) as u32);
    }

    #[test]
    fn test_rem_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REM),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // When dividing by zero, the result should be the dividend
        assert_eq!(cpu.registers.read(Register::X3), 20);
    }

    #[test]
    fn test_rem_overflow() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, i32::MIN as u32);
        cpu.registers.write(Register::X2, (-1i32) as u32);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REM),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // Special case: MIN_VALUE % -1 should be 0
        // This is because MIN_VALUE / -1 would overflow, so we define the result as 0
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_remu_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REMU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // 20 % 3 = 2 (unsigned)
        assert_eq!(cpu.registers.read(Register::X3), 2);
    }

    #[test]
    fn test_remu_large_numbers() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REMU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // 0xFFFFFFFF % 3 = 0
        // This is because 0xFFFFFFFF is 4294967295 in decimal, which is divisible by 3
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_remu_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::REMU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        // When dividing by zero, the result should be the dividend
        assert_eq!(cpu.registers.read(Register::X3), 20);
    }
}
