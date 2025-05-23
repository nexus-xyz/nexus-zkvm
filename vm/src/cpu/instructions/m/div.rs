use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

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
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_div_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(6));
        assert_eq!(cpu.registers.read(Register::X3), 6);
    }

    #[test]
    fn test_div_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-20i32) as u32);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-6i32) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (-6i32) as u32);
    }

    #[test]
    fn test_div_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-1i32) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (-1i32) as u32);
    }

    #[test]
    fn test_div_overflow() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, i32::MIN as u32);
        cpu.registers.write(Register::X2, (-1i32) as u32);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(i32::MIN as u32));
        assert_eq!(cpu.registers.read(Register::X3), i32::MIN as u32);
    }

    #[test]
    fn test_div_sign_combinations() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 25);
        cpu.registers.write(Register::X2, 5);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(5));
        assert_eq!(cpu.registers.read(Register::X3), 5);

        cpu.registers.write(Register::X1, 25);
        cpu.registers.write(Register::X2, (-5i32) as u32);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-5i32) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (-5i32) as u32);

        cpu.registers.write(Register::X1, (-25i32) as u32);
        cpu.registers.write(Register::X2, 5);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-5i32) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (-5i32) as u32);

        cpu.registers.write(Register::X1, (-25i32) as u32);
        cpu.registers.write(Register::X2, (-5i32) as u32);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(5));
        assert_eq!(cpu.registers.read(Register::X3), 5);
    }

    #[test]
    fn test_div_negative_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-42i32) as u32);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-1i32) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (-1i32) as u32);
    }

    #[test]
    fn test_div_zero_dividend() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0);
        cpu.registers.write(Register::X2, 5);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_div_almost_overflow() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, i32::MIN as u32);
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2);
        let mut instruction = DivInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((i32::MIN / 2) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (i32::MIN / 2) as u32);
    }

    #[test]
    fn test_divu_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(6));
        assert_eq!(cpu.registers.read(Register::X3), 6);
    }

    #[test]
    fn test_divu_large_numbers() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x7FFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0x7FFFFFFF);
    }

    #[test]
    fn test_divu_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(u32::MAX));
        assert_eq!(cpu.registers.read(Register::X3), u32::MAX);
    }

    #[test]
    fn test_divu_max_value() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, u32::MAX);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_divu_max_value_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(u32::MAX));
        assert_eq!(cpu.registers.read(Register::X3), u32::MAX);
    }

    #[test]
    fn test_divu_with_negative_values() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-10i32) as u32);
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        let expected = ((-10i32) as u32) / 2;
        assert_eq!(res, Some(expected));
        assert_eq!(cpu.registers.read(Register::X3), expected);
    }

    #[test]
    fn test_divu_zero_dividend() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0);
        cpu.registers.write(Register::X2, 5);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_divu_small_divisor() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 1000);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2);
        let mut instruction = DivuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(1000));
        assert_eq!(cpu.registers.read(Register::X3), 1000);
    }
}
