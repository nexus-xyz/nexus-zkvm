use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::Instruction,
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct BeqInstruction {
    rs1: u32,
    rs2: u32,
    imm: u32,
}

impl InstructionState for BeqInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <BeqInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <BeqInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    // Perhaps I move the comparison to execute stage?
    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        if self.rs1 == self.rs2 {
            cpu.pc_mut().branch(self.imm);
        } else {
            cpu.pc_mut().step();
        }

        Some(cpu.pc().value)
    }
}

impl InstructionExecutor for BeqInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rs1: registers[ins.op_a],
            rs2: registers[ins.op_b],
            imm: ins.op_c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_beq_branch_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set equal values in registers
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 2, 0x100);

        let instruction = BeqInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the beq instruction
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated)
        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc, 0x1100);
    }

    #[test]
    fn test_beq_branch_not_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set different values in registers
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 2, 0x100);

        let instruction = BeqInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the beq instruction
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc, 0x1004);
    }

    #[test]
    fn test_beq_zero_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set equal values in registers
        cpu.registers.write(Register::X1, 5);
        cpu.registers.write(Register::X2, 5);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 2, 0);

        let instruction = BeqInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the beq instruction
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken but PC didn't change due to zero offset
        assert_eq!(res, Some(0x1000));
        assert_eq!(cpu.pc, 0x1000);
    }

    #[test]
    fn test_beq_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set equal values in registers
        cpu.registers.write(Register::X1, 15);
        cpu.registers.write(Register::X2, 15);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 2, offset);

        let instruction = BeqInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the beq instruction
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated backwards)
        assert_eq!(res, Some(0xF00));
        assert_eq!(cpu.pc, 0xF00);
    }

    #[test]
    fn test_beq_same_register() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set a value in a register
        cpu.registers.write(Register::X1, 25);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 1, 0x100);

        let instruction = BeqInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the beq instruction
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (comparing a register with itself should always be equal)
        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc, 0x1100);
    }
}
