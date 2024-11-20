use nexus_common::cpu::Registers;
use nexus_vm::{
    cpu::RegisterFile,
    riscv::{InstructionType, Register},
    trace::Step,
    WORD_SIZE,
};

/// Program execution step.
#[derive(Debug, Default)]
pub struct ProgramStep {
    /// Machine registers.
    pub(crate) regs: RegisterFile,
    /// Program step.
    pub(crate) step: Step,
}

/// Represents a 32-bit word as 4 8-bit limbs in little-endian order
pub type Word = [u8; WORD_SIZE];

/// Represents a 32-bit word as 4 8-bit limbs in little-endian order,
/// along with the count of effective bits.
pub type WordWithEffectiveBits = (Word, usize);

impl ProgramStep {
    /// Returns the value of the second operand (rs1) as bytes.
    /// Always a register value in range u32.
    pub(crate) fn get_value_b(&self) -> Word {
        self.regs.read(self.step.instruction.op_b).to_le_bytes()
    }

    /// Returns the value of the third operand (rs2 or immediate) as bytes.
    /// The size of effective bits varies based on the instruction type.
    pub(crate) fn get_value_c(&self) -> WordWithEffectiveBits {
        let instruction = &self.step.instruction;
        let (value, effective_bits) = match instruction.ins_type {
            InstructionType::RType => (self.regs.read(Register::from(instruction.op_c as u8)), 32),
            InstructionType::IType | InstructionType::BType | InstructionType::SType => {
                (instruction.op_c, 12)
            }
            InstructionType::ITypeShamt => (instruction.op_c, 5),
            InstructionType::JType => (instruction.op_c, 20),
            InstructionType::UType => (instruction.op_c, 32),
            InstructionType::Unimpl => (0, 0),
        };

        (value.to_le_bytes(), effective_bits)
    }

    /// Returns the result computed in VM for cross-checking.
    pub(crate) fn get_result(&self) -> Option<Word> {
        self.step.result.map(|r| r.to_le_bytes())
    }

    /// Returns true if the valueA register is x0 register.
    pub(crate) fn value_a_effectitve_flag(&self) -> bool {
        self.step.instruction.op_a != Register::X0
    }

    /// Returns a step so that MachineChips can fill unused rows
    ///
    /// MachineChips will make sure padding steps don't cause constraint failures and don't affect memory checking
    pub fn padding() -> Self {
        let mut ret = Self::default();
        ret.step.is_padding = true;
        ret
    }
}
