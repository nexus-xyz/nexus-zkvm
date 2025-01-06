use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, Register},
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct AuipcInstruction {
    rd: Register,
    imm: u32,
}

impl InstructionState for AuipcInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <AuipcInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <AuipcInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        let new_pc = cpu.pc_mut().value.wrapping_add(self.imm << 12);
        cpu.registers_mut().write(self.rd, new_pc);

        Some(new_pc)
    }
}

impl InstructionExecutor for AuipcInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, _: &impl Registers) -> Self {
        Self {
            rd: ins.op_a,
            imm: ins.op_c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode};

    #[test]
    fn test_auipc_basic() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        let bare_instruction =
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 1, 0, 0x12345);

        let instruction = AuipcInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the auipc instruction
        let res = instruction.write_back(&mut cpu);

        // Check the result (0x1000 + 0x12345000 = 0x12346000)
        assert_eq!(res, Some(0x12346000));
        assert_eq!(cpu.registers.read(Register::X1), 0x12346000);
    }

    #[test]
    fn test_auipc_zero_immediate() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x2000;

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 2, 0, 0);

        let instruction = AuipcInstruction::decode(&bare_instruction, &cpu.registers);

        let res = instruction.write_back(&mut cpu);

        // With zero immediate, the result should be the current PC
        assert_eq!(res, Some(0x2000));
        assert_eq!(cpu.registers.read(Register::X2), 0x2000);
    }

    #[test]
    fn test_auipc_max_immediate() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        let bare_instruction =
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 3, 0, 0xFFFFF);

        let instruction = AuipcInstruction::decode(&bare_instruction, &cpu.registers);

        let res = instruction.write_back(&mut cpu);

        // 0x1000 + 0xFFFFF000 = 0xFFFFF000 + 0x1000 = 0x0
        assert_eq!(res, Some(0x0));
        assert_eq!(cpu.registers.read(Register::X3), 0x0);
    }

    #[test]
    fn test_auipc_overflow() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0xFFFFFFFF;

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 4, 0, 0x1);

        let instruction = AuipcInstruction::decode(&bare_instruction, &cpu.registers);

        let res = instruction.write_back(&mut cpu);

        // 0xFFFFFFFF + 0x1000 = 0xFFF (with overflow)
        assert_eq!(res, Some(0xFFF));
        assert_eq!(cpu.registers.read(Register::X4), 0xFFF);
    }

    #[test]
    fn test_auipc_multiple_instructions() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        let bare_instruction1 =
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 1, 0, 0x12345);
        let instruction1 = AuipcInstruction::decode(&bare_instruction1, &cpu.registers);
        let res1 = instruction1.write_back(&mut cpu);

        cpu.pc.value = 0x2000;

        let bare_instruction2 =
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 2, 0, 0x6789A);
        let instruction2 = AuipcInstruction::decode(&bare_instruction2, &cpu.registers);
        let res2 = instruction2.write_back(&mut cpu);

        assert_eq!(res1, Some(0x12346000));
        assert_eq!(res2, Some(0x6789C000));

        assert_eq!(cpu.registers.read(Register::X1), 0x12346000);
        assert_eq!(cpu.registers.read(Register::X2), 0x6789C000);
    }
}
