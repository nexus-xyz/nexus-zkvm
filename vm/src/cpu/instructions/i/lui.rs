use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor},
    },
    error::Result,
    memory::Memory,
    riscv::{Instruction, Register},
};

pub struct LuiInstruction {
    rd: Register,
    imm: u32,
}

impl InstructionExecutor for LuiInstruction {
    type InstructionState = Self;
    type Result = Result<Option<u32>>;

    fn decode(ins: &Instruction, _: &RegisterFile) -> Self {
        Self {
            rd: ins.op_a,
            imm: ins.op_c,
        }
    }

    fn memory_read(&mut self, _: &Memory) -> Self::Result {
        Ok(None)
    }

    fn memory_write(&self, _: &mut Memory) -> Self::Result {
        Ok(None)
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut Cpu) {
        cpu.registers.write(self.rd, self.imm << 12);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{Instruction, InstructionType, Opcode};

    #[test]
    fn test_lui_basic() {
        let mut cpu = Cpu::default();

        let bare_instruction = Instruction::new(Opcode::LUI, 1, 0, 0x12345, InstructionType::UType);

        let instruction = LuiInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the lui instruction
        instruction.write_back(&mut cpu);

        // Check the result (0x12345 << 12 = 0x12345000)
        assert_eq!(cpu.registers.read(Register::X1), 0x12345000);
    }

    #[test]
    fn test_lui_zero_immediate() {
        let mut cpu = Cpu::default();

        let bare_instruction = Instruction::new(Opcode::LUI, 2, 0, 0, InstructionType::UType);

        let instruction = LuiInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.write_back(&mut cpu);

        // With zero immediate, the result should be zero
        assert_eq!(cpu.registers.read(Register::X2), 0);
    }

    #[test]
    fn test_lui_max_immediate() {
        let mut cpu = Cpu::default();

        let bare_instruction = Instruction::new(Opcode::LUI, 3, 0, 0xFFFFF, InstructionType::UType);

        let instruction = LuiInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.write_back(&mut cpu);

        // 0xFFFFF << 12 = 0xFFFFF000
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFF000);
    }

    #[test]
    fn test_lui_overwrite() {
        let mut cpu = Cpu::default();

        // First, set a value in the register
        cpu.registers.write(Register::X4, 0xFFFFFFFF);

        let bare_instruction = Instruction::new(Opcode::LUI, 4, 0, 0x12345, InstructionType::UType);

        let instruction = LuiInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.write_back(&mut cpu);

        // The LUI instruction should completely overwrite the previous value
        assert_eq!(cpu.registers.read(Register::X4), 0x12345000);
    }

    #[test]
    fn test_lui_multiple_instructions() {
        let mut cpu = Cpu::default();

        let bare_instruction1 =
            Instruction::new(Opcode::LUI, 1, 0, 0x12345, InstructionType::UType);
        let instruction1 = LuiInstruction::decode(&bare_instruction1, &cpu.registers);
        instruction1.write_back(&mut cpu);

        let bare_instruction2 =
            Instruction::new(Opcode::LUI, 2, 0, 0x6789A, InstructionType::UType);
        let instruction2 = LuiInstruction::decode(&bare_instruction2, &cpu.registers);
        instruction2.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X1), 0x12345000);
        assert_eq!(cpu.registers.read(Register::X2), 0x6789A000);
    }

    #[test]
    fn test_lui_lower_bits_unaffected() {
        let mut cpu = Cpu::default();

        // Set a value with non-zero lower 12 bits
        cpu.registers.write(Register::X5, 0x00000FFF);

        let bare_instruction = Instruction::new(Opcode::LUI, 5, 0, 0x12345, InstructionType::UType);

        let instruction = LuiInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.write_back(&mut cpu);

        // LUI should overwrite the upper 20 bits, leaving lower 12 bits as zero
        assert_eq!(cpu.registers.read(Register::X5), 0x12345000);
    }
}
