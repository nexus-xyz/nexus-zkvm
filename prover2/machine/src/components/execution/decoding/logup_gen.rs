//! Logup trace generation helpers for execution components.

use stwo_prover::core::{backend::simd::column::BaseColumn, fields::m31::BaseField};

use nexus_vm::{riscv::Register, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{component::FinalizedColumn, program::ProgramStep};

/// Column for indexing virtual decoding trace, these values are used by the prover
/// for the program memory checking logup trace generation.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum DecodingColumn {
    /// The address of the first operand of the instruction
    #[size = 1]
    OpA,
    /// The 32-bit instruction word stored at address pc
    #[size = 4]
    InstrVal,
}

/// Execution component decoding trace.
///
/// Prover doesn't commit to this trace.
pub struct ComponentDecodingTrace<'a> {
    log_size: u32,
    trace: Vec<BaseColumn>,
    program_steps: Vec<ProgramStep<'a>>,
}

impl<'a> ComponentDecodingTrace<'a> {
    pub fn new<I: Iterator<Item = ProgramStep<'a>>>(log_size: u32, iter: I) -> Self {
        let program_steps: Vec<ProgramStep<'a>> = iter.collect();
        let pad_len = (1usize << log_size)
            .checked_sub(program_steps.len())
            .expect("padding underflow caused by incorrect log size");

        let mut result = Vec::with_capacity(DecodingColumn::COLUMNS_NUM);

        let op_a_iter = program_steps
            .iter()
            .map(|step| step.get_op_a() as u8 as u32)
            .chain(std::iter::repeat_n(0, pad_len));

        result.push(BaseColumn::from_iter(op_a_iter.map(BaseField::from)));
        for i in 0..WORD_SIZE {
            let col_iter = program_steps
                .iter()
                .map(|step| (step.step.raw_instruction >> (i * 8)) & 255)
                .chain(std::iter::repeat_n(0, pad_len));
            result.push(BaseColumn::from_iter(col_iter.map(BaseField::from)));
        }
        Self {
            log_size,
            trace: result,
            program_steps,
        }
    }

    pub fn base_column<const N: usize>(&self, col: DecodingColumn) -> [FinalizedColumn; N] {
        assert_eq!(col.size(), N, "decoding column size mismatch");

        let offset = col.offset();
        std::array::from_fn(|i| (&self.trace[i + offset]).into())
    }

    pub fn a_val(&self) -> [FinalizedColumn; WORD_SIZE] {
        self.reg_value_bytes(ProgramStep::get_reg3_result_value)
    }

    pub fn b_val(&self) -> [FinalizedColumn; WORD_SIZE] {
        self.reg_value_bytes(ProgramStep::get_value_b)
    }

    pub fn c_val(&self) -> [FinalizedColumn; WORD_SIZE] {
        self.reg_value_bytes(|step| step.get_value_c().0)
    }

    pub fn op_b(&self) -> FinalizedColumn {
        self.reg_addr(ProgramStep::get_op_b)
    }

    pub fn op_c(&self) -> FinalizedColumn {
        self.reg_addr(|step| {
            Register::from(
                u8::try_from(step.step.instruction.op_c).expect("op_c register address overflow"),
            )
        })
    }

    fn reg_addr<F>(&self, f: F) -> FinalizedColumn
    where
        F: Fn(&ProgramStep<'a>) -> Register,
    {
        let pad_len = (1usize << self.log_size) - self.program_steps.len();
        let reg: Vec<Register> = self.program_steps.iter().map(f).collect();

        let reg_iter = reg
            .into_iter()
            .map(|r| r as u32)
            .chain(std::iter::repeat_n(0, pad_len));
        let col = BaseColumn::from_iter(reg_iter.map(BaseField::from));
        FinalizedColumn::new_virtual(col)
    }

    fn reg_value_bytes<F>(&self, f: F) -> [FinalizedColumn; WORD_SIZE]
    where
        F: Fn(&ProgramStep<'a>) -> [u8; WORD_SIZE],
    {
        let pad_len = (1usize << self.log_size) - self.program_steps.len();
        let bytes: Vec<[u8; WORD_SIZE]> = self.program_steps.iter().map(f).collect();

        std::array::from_fn(|i| {
            let col_iter = bytes
                .iter()
                .map(|b| b[i] as u32)
                .chain(std::iter::repeat_n(0, pad_len));
            let col = BaseColumn::from_iter(col_iter.map(BaseField::from));
            FinalizedColumn::new_virtual(col)
        })
    }
}
