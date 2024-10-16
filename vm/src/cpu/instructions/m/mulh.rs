use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct MulhInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(MulhInstruction, |a: u32, b: u32| {
    let a_signed = a as i32 as i64;
    let b_signed = b as i32 as i64;
    (a_signed.wrapping_mul(b_signed) >> 32) as i32 as u32
});

pub struct MulhuInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(MulhuInstruction, |a: u32, b: u32| {
    let a_unsigned = a as u64;
    let b_unsigned = b as u64;
    (a_unsigned.wrapping_mul(b_unsigned) >> 32) as u32
});

pub struct MulhsuInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(MulhsuInstruction, |a: u32, b: u32| {
    let a_signed = a as i32 as i64;
    let b_unsigned = b as u64;
    (a_signed.wrapping_mul(b_unsigned as i64) >> 32) as i32 as u32
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_mulh_positive_numbers() {
        let mut cpu = Cpu::default();

        // Set up two large positive numbers
        cpu.registers.write(Register::X1, 0x7FFFFFFF); // 2^31 - 1
        cpu.registers.write(Register::X2, 0x7FFFFFFF); // 2^31 - 1

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULH),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: (2^31 - 1)^2 = 2^62 - 2^32 + 1
        // Upper 32 bits: 0x3FFFFFFF
        assert_eq!(res, Some(0x3FFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0x3FFFFFFF);
    }

    #[test]
    fn test_mulh_negative_numbers() {
        let mut cpu = Cpu::default();

        // Set up two large negative numbers
        cpu.registers.write(Register::X1, 0x80000000); // -2^31
        cpu.registers.write(Register::X2, 0x80000000); // -2^31

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULH),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: (-2^31) * (-2^31) = 2^62
        // Upper 32 bits: 0x40000000
        assert_eq!(res, Some(0x40000000));
        assert_eq!(cpu.registers.read(Register::X3), 0x40000000);
    }

    #[test]
    fn test_mulh_positive_and_negative() {
        let mut cpu = Cpu::default();

        // Set up one large positive and one large negative number
        cpu.registers.write(Register::X1, 0x7FFFFFFF); // 2^31 - 1
        cpu.registers.write(Register::X2, 0x80000000); // -2^31

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULH),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: (2^31 - 1) * (-2^31) = -2^62 + 2^31
        // Upper 32 bits: 0xC0000000
        assert_eq!(res, Some(0xC0000000));
        assert_eq!(cpu.registers.read(Register::X3), 0xC0000000);
    }

    #[test]
    fn test_mulh_small_numbers() {
        let mut cpu = Cpu::default();

        // Set up two small numbers
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULH),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: 10 * 20 = 200, which fits in 32 bits
        // Upper 32 bits should be 0
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_mulhu_large_unsigned() {
        let mut cpu = Cpu::default();

        // Set up two large unsigned numbers
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // 2^32 - 1
        cpu.registers.write(Register::X2, 0xFFFFFFFF); // 2^32 - 1

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: (2^32 - 1)^2 = 2^64 - 2^33 + 1
        // Upper 32 bits: 0xFFFFFFFE
        assert_eq!(res, Some(0xFFFFFFFE));
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFE);
    }

    #[test]
    fn test_mulhu_large_and_small() {
        let mut cpu = Cpu::default();

        // Set up one large and one small unsigned number
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // 2^32 - 1
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: (2^32 - 1) * 2 = 2^33 - 2
        // Upper 32 bits: 1
        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_mulhu_medium_numbers() {
        let mut cpu = Cpu::default();

        // Set up two medium-sized unsigned numbers
        cpu.registers.write(Register::X1, 0x80000000); // 2^31
        cpu.registers.write(Register::X2, 0x80000000); // 2^31

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: 2^31 * 2^31 = 2^62
        // Upper 32 bits: 0x40000000
        assert_eq!(res, Some(0x40000000));
        assert_eq!(cpu.registers.read(Register::X3), 0x40000000);
    }

    #[test]
    fn test_mulhu_small_numbers() {
        let mut cpu = Cpu::default();

        // Set up two small numbers
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: 10 * 20 = 200, which fits in 32 bits
        // Upper 32 bits should be 0
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_mulhu_zero() {
        let mut cpu = Cpu::default();

        // Set up one zero and one non-zero number
        cpu.registers.write(Register::X1, 0);
        cpu.registers.write(Register::X2, 0xFFFFFFFF);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: 0 * (2^32 - 1) = 0
        // Upper 32 bits should be 0
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_mulhsu_positive_signed_large_unsigned() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x7FFFFFFF); // 2^31 - 1 (largest positive signed 32-bit integer)
        cpu.registers.write(Register::X2, 0xFFFFFFFF); // 2^32 - 1 (largest unsigned 32-bit integer)

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHSU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhsuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: (2^31 - 1) * (2^32 - 1) = 2^63 - 2^32 + 2^31 - 1
        // Upper 32 bits: 0x7FFFFFFE
        assert_eq!(res, Some(0x7FFFFFFE));
        assert_eq!(cpu.registers.read(Register::X3), 0x7FFFFFFE);
    }

    #[test]
    fn test_mulhsu_negative_signed_large_unsigned() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x80000000); // -2^31 (smallest negative signed 32-bit integer)
        cpu.registers.write(Register::X2, 0xFFFFFFFF); // 2^32 - 1 (largest unsigned 32-bit integer)

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHSU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhsuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: -2^31 * (2^32 - 1) = -2^63 + 2^31
        // Upper 32 bits: 0x80000000
        assert_eq!(res, Some(0x80000000));
        assert_eq!(cpu.registers.read(Register::X3), 0x80000000);
    }

    #[test]
    fn test_mulhsu_small_numbers() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 10); // Small positive signed number
        cpu.registers.write(Register::X2, 20); // Small unsigned number

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHSU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhsuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: 10 * 20 = 200, which fits in lower 32 bits
        // Upper 32 bits: 0
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_mulhsu_negative_small_signed() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xFFFFFFFB); // -5 in two's complement
        cpu.registers.write(Register::X2, 20); // Small unsigned number

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::MULHSU),
            3,
            1,
            2,
            InstructionType::RType,
        );
        let mut instruction = MulhsuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Expected result: -5 * 20 = -100, which fits in lower 32 bits
        // Upper 32 bits: 0xFFFFFFFF (due to sign extension)
        assert_eq!(res, Some(0xFFFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFF);
    }
}
