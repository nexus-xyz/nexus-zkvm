use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
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
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_rem_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // 20 % 3 = 2
        assert_eq!(res, Some(2));
        assert_eq!(cpu.registers.read(Register::X3), 2);
    }

    #[test]
    fn test_rem_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-20i32) as u32);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // -20 % 3 = -2
        // The result is negative because the dividend is negative
        assert_eq!(res, Some((-2i32) as u32));
        assert_eq!(cpu.registers.read(Register::X3), (-2i32) as u32);
    }

    #[test]
    fn test_rem_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // When dividing by zero, the result should be the dividend
        assert_eq!(res, Some(20));
        assert_eq!(cpu.registers.read(Register::X3), 20);
    }

    #[test]
    fn test_rem_overflow() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, i32::MIN as u32);
        cpu.registers.write(Register::X2, (-1i32) as u32);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Special case: MIN_VALUE % -1 should be 0
        // This is because MIN_VALUE / -1 would overflow, so we define the result as 0
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    // Additional sign tests for REM
    #[test]
    fn test_rem_sign_combinations() {
        // Test all four sign combinations for dividend and divisor

        // Case 1: Positive % Positive (positive remainder)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 25); // Positive dividend
        cpu.registers.write(Register::X2, 7); // Positive divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(4)); // 25 % 7 = 4
        assert_eq!(cpu.registers.read(Register::X3), 4);

        // Case 2: Positive % Negative (positive remainder)
        cpu.registers.write(Register::X1, 25); // Positive dividend
        cpu.registers.write(Register::X2, (-7i32) as u32); // Negative divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(4)); // 25 % -7 = 4 (sign of dividend)
        assert_eq!(cpu.registers.read(Register::X3), 4);

        // Case 3: Negative % Positive (negative remainder)
        cpu.registers.write(Register::X1, (-25i32) as u32); // Negative dividend
        cpu.registers.write(Register::X2, 7); // Positive divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-4i32) as u32)); // -25 % 7 = -4 (sign of dividend)
        assert_eq!(cpu.registers.read(Register::X3), (-4i32) as u32);

        // Case 4: Negative % Negative (negative remainder)
        cpu.registers.write(Register::X1, (-25i32) as u32); // Negative dividend
        cpu.registers.write(Register::X2, (-7i32) as u32); // Negative divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-4i32) as u32)); // -25 % -7 = -4 (sign of dividend)
        assert_eq!(cpu.registers.read(Register::X3), (-4i32) as u32);
    }

    #[test]
    fn test_rem_negative_by_zero() {
        // Test remainder of a negative number by zero (should return the dividend)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-42i32) as u32); // Negative dividend
        cpu.registers.write(Register::X2, 0); // Zero divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some((-42i32) as u32)); // Should return the dividend
        assert_eq!(cpu.registers.read(Register::X3), (-42i32) as u32);
    }

    #[test]
    fn test_rem_zero_dividend() {
        // Test remainder of zero by a non-zero number (should return 0)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0); // Zero dividend
        cpu.registers.write(Register::X2, 5); // Non-zero divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0)); // 0 % 5 = 0
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_rem_divisor_is_one() {
        // Test remainder with divisor of 1 (should always be 0)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 42); // Dividend
        cpu.registers.write(Register::X2, 1); // Divisor is 1

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0)); // Any number % 1 = 0
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_rem_large_values() {
        // Test remainder with large values
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, i32::MAX as u32); // MAX_INT dividend
        cpu.registers.write(Register::X2, 10); // Divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2);
        let mut instruction = RemInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Calculate expected remainder: MAX_INT % 10
        let expected = (i32::MAX % 10) as u32;
        assert_eq!(res, Some(expected));
        assert_eq!(cpu.registers.read(Register::X3), expected);
    }

    #[test]
    fn test_remu_normal() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // 20 % 3 = 2 (unsigned)
        assert_eq!(res, Some(2));
        assert_eq!(cpu.registers.read(Register::X3), 2);
    }

    #[test]
    fn test_remu_large_numbers() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // 0xFFFFFFFF % 3 = 0
        // This is because 0xFFFFFFFF is 4294967295 in decimal, which is divisible by 3
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_remu_by_zero() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // When dividing by zero, the result should be the dividend
        assert_eq!(res, Some(20));
        assert_eq!(cpu.registers.read(Register::X3), 20);
    }

    // Additional tests for REMU
    #[test]
    fn test_remu_max_value_by_nonzero() {
        // Test REMU with MAX_VALUE and a non-zero divisor
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, u32::MAX); // MAX dividend
        cpu.registers.write(Register::X2, 10); // Divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Calculate expected: MAX_UINT % 10
        let expected = u32::MAX % 10;
        assert_eq!(res, Some(expected));
        assert_eq!(cpu.registers.read(Register::X3), expected);
    }

    #[test]
    fn test_remu_with_negative_values() {
        // Test REMU with values that would be negative in signed interpretation
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, (-10i32) as u32); // Negative as signed, large as unsigned
        cpu.registers.write(Register::X2, 3); // Divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Compute the expected remainder for an unsigned interpretation of -10 % 3
        let expected = ((-10i32) as u32) % 3;
        assert_eq!(res, Some(expected));
        assert_eq!(cpu.registers.read(Register::X3), expected);
    }

    #[test]
    fn test_remu_zero_dividend() {
        // Test division of zero by a non-zero number (should return 0)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0); // Zero dividend
        cpu.registers.write(Register::X2, 5); // Non-zero divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0)); // 0 % 5 = 0
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_remu_divisor_is_one() {
        // Test remainder with divisor of 1 (should always be 0)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 42); // Dividend
        cpu.registers.write(Register::X2, 1); // Divisor is 1

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0)); // Any number % 1 = 0
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_remu_max_by_zero() {
        // Test MAX_VALUE % 0
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, u32::MAX); // MAX dividend
        cpu.registers.write(Register::X2, 0); // Zero divisor

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(u32::MAX)); // Should return the dividend
        assert_eq!(cpu.registers.read(Register::X3), u32::MAX);
    }

    #[test]
    fn test_remu_dividend_less_than_divisor() {
        // Test remainder when dividend < divisor (should return dividend)
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 3); // Dividend
        cpu.registers.write(Register::X2, 10); // Divisor (larger than dividend)

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2);
        let mut instruction = RemuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(3)); // 3 % 10 = 3
        assert_eq!(cpu.registers.read(Register::X3), 3);
    }
}
