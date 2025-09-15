use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, Register},
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct JalInstruction {
    rd: Register,
    imm: u32,
}

impl InstructionState for JalInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <JalInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <JalInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        let next_addr = cpu.pc().value + 4;
        cpu.registers_mut().write(self.rd, next_addr);
        cpu.pc_mut().jal(self.imm);

        Some(next_addr)
    }
}

impl InstructionExecutor for JalInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, _: &impl Registers) -> Self {
        Self {
            rd: ins.op_a,
            imm: ins.op_c,
        }
    }
}

pub struct JalrInstruction {
    rd: Register,
    rs1: u32,
    imm: u32,
}

impl InstructionState for JalrInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <JalrInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <JalrInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        let tmp = cpu.pc().value;
        cpu.pc_mut().jalr(self.rs1, self.imm);
        cpu.registers_mut().write(self.rd, tmp + 4);

        Some(tmp + 4)
    }
}

impl InstructionExecutor for JalrInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, register: &impl Registers) -> Self {
        Self {
            rd: ins.op_a,
            rs1: register[ins.op_b],
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
    fn test_jal_positive_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Use a positive offset (0x100)
        let offset = 0x100;
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::JAL), 1, 0, offset);
        let instruction = JalInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jal instruction
        let res = instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated forwards)
        assert_eq!(cpu.pc.value, 0x1100);

        // Check if the link address was stored correctly
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.registers.read(Register::X1), 0x1004);
    }

    #[test]
    fn test_jal_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::JAL), 2, 0, offset);
        let instruction = JalInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jal instruction
        let res = instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated backwards)
        assert_eq!(cpu.pc.value, 0xF00);

        // Check if the link address was stored correctly
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.registers.read(Register::X2), 0x1004);
    }

    #[test]
    fn test_jalr_positive_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set base address in rs1
        cpu.registers.write(Register::X1, 0x2000);

        // Use a positive offset (0x100)
        let offset = 0x100;
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 2, 1, offset);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        let res = instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated to rs1 + offset)
        assert_eq!(cpu.pc.value, 0x2100);

        // Check if the link address was stored correctly
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.registers.read(Register::X2), 0x1004);
    }

    #[test]
    fn test_jalr_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set base address in rs1
        cpu.registers.write(Register::X1, 0x2000);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 3, 1, offset);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        let res = instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated to rs1 + offset)
        assert_eq!(cpu.pc.value, 0x1F00);

        // Check if the link address was stored correctly
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.registers.read(Register::X3), 0x1004);
    }

    #[test]
    fn test_jalr_zero_register() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Use x0 as rs1 (should always be 0)
        let offset = 0x100;
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 4, 0, offset);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        let res = instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated to offset only, since x0 is always 0)
        assert_eq!(cpu.pc.value, 0x100);

        // Check if the link address was stored correctly
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.registers.read(Register::X4), 0x1004);
    }

    #[test]
    fn test_jalr_alignment_masks_lsb() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set base address in rs1 to an odd value
        cpu.registers.write(Register::X1, 0x2001);

        // Use offset that keeps sum odd: 0x0 (so 0x2001 + 0x0)
        let offset = 0x0;
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 5, 1, offset);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        let _ = instruction.write_back(&mut cpu);

        // PC must have LSB cleared to enforce 2-byte alignment
        assert_eq!(cpu.pc.value, 0x2000);
    }
}
