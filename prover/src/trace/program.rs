use nexus_common::cpu::Registers;
use nexus_vm::{
    cpu::RegisterFile,
    riscv::{InstructionType, Register},
    trace::{Step, Trace},
    WORD_SIZE,
};

/// Program execution step.
#[derive(Clone, Debug, Default)]
pub struct ProgramStep {
    /// Machine registers.
    pub(crate) regs: RegisterFile,
    /// Program step.
    pub(crate) step: Step,
}

/// Represents a 32-bit word as 4 8-bit limbs in little-endian order
pub type Word = [u8; WORD_SIZE];
/// Represents a 32-bit word as 4 1-bit limbs in little-endian order
/// It is used for carry/borrow bits.
pub type BoolWord = [bool; WORD_SIZE];

/// Represents a 32-bit word as 4 8-bit limbs in little-endian order,
/// along with the count of effective bits.
pub type WordWithEffectiveBits = (Word, usize);

impl ProgramStep {
    /// Returns the value of the first operand (rd or rs1) as bytes.
    /// Always a register value in range u32.
    pub(crate) fn get_value_a(&self) -> Word {
        self.regs.read(self.step.instruction.op_a).to_le_bytes()
    }

    /// Returns the value of the second operand (rs1 or rs2) as bytes.
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

    /// Returns the signed bit of ValueA
    pub(crate) fn get_sgn_a(&self) -> bool {
        let a = self.get_value_a();
        (a[WORD_SIZE - 1] >> 7) == 1
    }

    /// Returns the signed bit of ValueB
    pub(crate) fn get_sgn_b(&self) -> bool {
        let b = self.get_value_b();
        (b[WORD_SIZE - 1] >> 7) == 1
    }

    /// Returns the signed bit of ValueC
    pub(crate) fn get_sgn_c(&self) -> bool {
        let c = self.get_value_c().0;
        (c[WORD_SIZE - 1] >> 7) == 1
    }
}

/// Iterates over the program steps in `trace``, padded to `num_rows` with `None`
///
/// Panics if `trace` contains more than `num_rows` steps.
pub fn iter_program_steps<TR: Trace>(
    trace: &TR,
    num_rows: usize,
) -> impl Iterator<Item = Option<ProgramStep>> + '_ {
    assert!(trace.get_num_steps() <= num_rows, "Too many ProgramSteps");
    trace
        .get_blocks_iter()
        .map(|block| {
            assert_eq!(block.steps.len(), 1, "Only k = 1 traces are supported.");
            Some(ProgramStep {
                step: block.steps[0].clone(),
                regs: block.regs,
            })
        })
        .chain(std::iter::repeat(None))
        .take(num_rows)
}
