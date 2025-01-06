use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct SraInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

impl InstructionState for SraInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <SraInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <SraInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {
        // Cast rs1 to i32 to perform arithmetic shift
        let rs1_signed = self.rs1 as i32;

        // Perform arithmetic right shift
        let result = rs1_signed >> (self.rs2 & 0x1F);

        // Cast the result back to u32
        self.rd.1 = result as u32;
    }

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        cpu.registers_mut().write(self.rd.0, self.rd.1);
        Some(self.rd.1)
    }
}

impl InstructionExecutor for SraInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: match ins.ins_type {
                InstructionType::RType => registers[Register::from(ins.op_c as u8)],
                _ => ins.op_c,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cpu::Cpu,
        riscv::{BuiltinOpcode, Opcode},
    };

    #[test]
    fn test_sra_small_positive() {
        let mut cpu = Cpu::default();
        cpu.registers
            .write(Register::X1, 0b0000_0000_0000_0000_0000_0000_0001_1010); // 26
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 3, 1, 2);
        let mut instruction = SraInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0b0000_0000_0000_0000_0000_0000_0000_0110));
        assert_eq!(
            cpu.registers.read(Register::X3),
            0b0000_0000_0000_0000_0000_0000_0000_0110
        ); // 6
    }

    #[test]
    fn test_sra_positive() {
        let mut cpu = Cpu::default();
        cpu.registers
            .write(Register::X1, 0b1000_0000_0000_0000_0000_0000_0000_0000); // 2^31
        cpu.registers.write(Register::X2, 4);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 3, 1, 2);
        let mut instruction = SraInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0b1111_1000_0000_0000_0000_0000_0000_0000));
        assert_eq!(
            cpu.registers.read(Register::X3),
            0b1111_1000_0000_0000_0000_0000_0000_0000
        );
    }

    #[test]
    fn test_sra_negative() {
        let mut cpu = Cpu::default();
        cpu.registers
            .write(Register::X1, 0b1111_1111_1111_1111_1111_1111_1111_1000); // -8
        cpu.registers.write(Register::X2, 2);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 3, 1, 2);
        let mut instruction = SraInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0b1111_1111_1111_1111_1111_1111_1111_1110));
        assert_eq!(
            cpu.registers.read(Register::X3),
            0b1111_1111_1111_1111_1111_1111_1111_1110
        ); // -2
    }

    #[test]
    fn test_sra_zero_shift() {
        let mut cpu = Cpu::default();
        cpu.registers
            .write(Register::X1, 0b1010_1010_1010_1010_1010_1010_1010_1010);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 3, 1, 2);
        let mut instruction = SraInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0b1010_1010_1010_1010_1010_1010_1010_1010));
        assert_eq!(
            cpu.registers.read(Register::X3),
            0b1010_1010_1010_1010_1010_1010_1010_1010
        );
    }

    #[test]
    fn test_sra_large_shift() {
        let mut cpu = Cpu::default();
        cpu.registers
            .write(Register::X1, 0b1000_0000_0000_0000_0000_0000_0000_0000); // 2^31
        cpu.registers.write(Register::X2, 31);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 3, 1, 2);
        let mut instruction = SraInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0b1111_1111_1111_1111_1111_1111_1111_1111));
        assert_eq!(
            cpu.registers.read(Register::X3),
            0b1111_1111_1111_1111_1111_1111_1111_1111
        ); // -1
    }

    #[test]
    fn test_sra_shift_more_than_32() {
        let mut cpu = Cpu::default();
        cpu.registers
            .write(Register::X1, 0b1000_0000_0000_0000_0000_0000_0000_0000); // 2^31
        cpu.registers.write(Register::X2, 33); // Should be equivalent to shifting by 1

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 3, 1, 2);
        let mut instruction = SraInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0b1100_0000_0000_0000_0000_0000_0000_0000));
        assert_eq!(
            cpu.registers.read(Register::X3),
            0b1100_0000_0000_0000_0000_0000_0000_0000
        );
    }
}
