//! Logup trace generation helpers for execution components.

use std::marker::PhantomData;

use nexus_common::constants::WORD_SIZE_HALVED;
use stwo_prover::core::{backend::simd::column::BaseColumn, fields::m31::BaseField};

use nexus_vm::{riscv::Register, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    component::{ComponentTrace, FinalizedColumn},
    program::ProgramStep,
};

/// Column for indexing virtual execution trace, these values are used by the prover
/// for the logup trace generation.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum ExecutionComponentColumn {
    /// The address of the first operand of the instruction
    #[size = 1]
    OpA,
    /// The 32-bit instruction word stored at address pc
    #[size = 2]
    InstrVal,
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The next execution time represented by two 16-bit limbs
    #[size = 2]
    ClkNext,
    /// The current value of the program counter
    #[size = 2]
    Pc,
    /// The next value of the program counter after execution
    #[size = 2]
    PcNext,
}

/// Execution component common trace.
///
/// Prover doesn't commit to this trace.
pub struct ExecutionComponentTrace<'a> {
    trace: Vec<BaseColumn>,

    pub(crate) log_size: u32,
    pub(crate) program_steps: Vec<ProgramStep<'a>>,
}

/// Appends a column to the trace by applying a closure to each program step.
///
/// Extends the trace with `pad_len` zeroes.
fn extend_trace_with<'a, F>(
    result: &mut Vec<BaseColumn>,
    pad_len: usize,
    program_steps: &[ProgramStep<'a>],
    f: F,
) where
    F: Fn(&ProgramStep<'a>) -> u32,
{
    let iter = program_steps
        .iter()
        .map(f)
        .chain(std::iter::repeat_n(0, pad_len));
    result.push(BaseColumn::from_iter(iter.map(BaseField::from)));
}

impl<'a> ExecutionComponentTrace<'a> {
    pub fn new<I: Iterator<Item = ProgramStep<'a>>>(log_size: u32, iter: I) -> Self {
        let program_steps: Vec<ProgramStep<'a>> = iter.collect();
        let pad_len = (1usize << log_size)
            .checked_sub(program_steps.len())
            .expect("padding underflow caused by incorrect log size");

        let mut result = Vec::with_capacity(ExecutionComponentColumn::COLUMNS_NUM);

        // op-a is used by all components
        extend_trace_with(&mut result, pad_len, &program_steps, |step| {
            step.get_op_a() as u8 as u32
        });
        // instr-val
        for i in 0..WORD_SIZE_HALVED {
            extend_trace_with(&mut result, pad_len, &program_steps, |step| {
                (step.step.raw_instruction >> (i * 16)) & 0xFFFF
            });
        }
        // clk
        for i in 0..WORD_SIZE_HALVED {
            extend_trace_with(&mut result, pad_len, &program_steps, |step| {
                (step.step.timestamp >> (i * 16)) & 0xFFFF
            });
        }
        // clk-next
        for i in 0..WORD_SIZE_HALVED {
            extend_trace_with(&mut result, pad_len, &program_steps, |step| {
                ((step.step.timestamp + 1) >> (i * 16)) & 0xFFFF
            });
        }
        // pc
        for i in 0..WORD_SIZE_HALVED {
            extend_trace_with(&mut result, pad_len, &program_steps, |step| {
                (step.step.pc >> (i * 16)) & 0xFFFF
            });
        }
        // pc-next
        for i in 0..WORD_SIZE_HALVED {
            extend_trace_with(&mut result, pad_len, &program_steps, |step| {
                (step.step.next_pc >> (i * 16)) & 0xFFFF
            });
        }
        Self {
            log_size,
            trace: result,
            program_steps,
        }
    }

    pub fn base_column<const N: usize>(
        &self,
        col: ExecutionComponentColumn,
    ) -> [FinalizedColumn; N] {
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

/// Reference to the part of the committed trace.
pub struct ComponentTraceRef<'a, C, D> {
    original_trace: &'a [BaseColumn],
    _phantom: PhantomData<(C, D)>,
}

impl<'a, C: AirColumn, D: AirColumn> ComponentTraceRef<'a, C, D> {
    /// Splits the component trace assuming it is a concatenation of air columns `C` and `D`,
    /// and returns a reference to the `D` part.
    pub fn split(component_trace: &'a ComponentTrace) -> Self {
        assert!(component_trace.original_trace.len() >= C::COLUMNS_NUM + D::COLUMNS_NUM);
        let original_trace = &component_trace.original_trace[C::COLUMNS_NUM..];
        Self {
            original_trace,
            _phantom: PhantomData,
        }
    }

    pub fn base_column<const N: usize>(&self, col: D) -> [FinalizedColumn; N] {
        assert_eq!(col.size(), N, "decoding column size mismatch");

        let offset = col.offset();
        std::array::from_fn(|i| (&self.original_trace[i + offset]).into())
    }
}
