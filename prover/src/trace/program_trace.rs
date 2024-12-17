use itertools::Itertools;
use num_traits::Zero;

use stwo_prover::core::{
    backend::{
        simd::{column::BaseColumn, m31::LOG_N_LANES},
        Backend,
    },
    fields::m31::BaseField,
    poly::{circle::CircleEvaluation, BitReversedOrder},
    ColumnVec,
};

use super::{
    utils::{bit_reverse, coset_order_to_circle_domain_order},
    IntoBaseFields, Traces,
};
use crate::column::ProgramColumn;

use nexus_vm::{emulator::ProgramMemoryEntry, WORD_SIZE};

/// Program (constant) trace containing [`ProgramColumn`].
///
/// These columns contain the whole program. They don't depend on the runtime information. The commitment of the program trace will be checked by the verifier.
/// pc_offset is the program counter written on the first row. The current assumption is that the program is in contiguous memory starting from pc_offset.
/// pc_offset is used by the program memory checking when it computes the row index corresponding to a pc value.
pub struct ProgramTraces {
    traces: Traces,
    pc_offset: u32,
    num_instructions: usize,
}

impl ProgramTraces {
    /// Returns [`ProgramColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length, filled with program content.
    pub fn new<I>(log_size: u32, program: I) -> Self
    where
        I: IntoIterator<Item = ProgramMemoryEntry>,
    {
        assert!(log_size >= LOG_N_LANES);
        let cols = vec![vec![BaseField::zero(); 1 << log_size]; ProgramColumn::COLUMNS_NUM];
        let mut ret = Self {
            traces: Traces { cols, log_size },
            pc_offset: 0u32,
            num_instructions: 0usize,
        };
        for (
            row_idx,
            ProgramMemoryEntry {
                pc,
                instruction_word,
            },
        ) in program.into_iter().enumerate()
        {
            if row_idx == 0 {
                ret.pc_offset = pc;
            }
            ret.num_instructions += 1;
            assert_eq!(
                row_idx * WORD_SIZE + ret.pc_offset as usize,
                pc as usize,
                "The program is assumed to be in contiguous memory."
            );
            ret.fill_program_columns(row_idx, pc, ProgramColumn::PrgMemoryPc);
            ret.fill_program_columns(row_idx, instruction_word, ProgramColumn::PrgMemoryWord);
            ret.fill_program_columns(row_idx, true, ProgramColumn::PrgMemoryFlag);
        }
        ret
    }

    pub fn dummy(log_size: u32) -> Self {
        Self::new(log_size, [])
    }

    /// Returns the log_size of columns.
    pub fn log_size(&self) -> u32 {
        self.traces.log_size
    }

    /// Returns a copy of `N` raw columns in range `[offset..offset + N]` in the bit-reversed BaseColumn format.
    ///
    /// This function allows SIMD-aware stwo libraries (for instance, logup) to read columns in the format they expect.
    /// It's desirable to merge this function with get_base_column() by turning PreprocessedColumn into a type-parameter,
    /// but that requires a Rust experimental feature called `const_trait_impl`. We avoid Rust experimental features.
    pub fn get_base_column<const N: usize>(&self, col: ProgramColumn) -> [BaseColumn; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        self.traces.cols[col.offset()..]
            .iter()
            .take(N)
            .map(|column_in_trace_order| {
                let mut tmp_col =
                    coset_order_to_circle_domain_order(column_in_trace_order.as_slice());
                bit_reverse(&mut tmp_col);
                BaseColumn::from_iter(tmp_col)
            })
            .collect_vec()
            .try_into()
            .expect("wrong size?")
    }

    /// Converts preprocessed traces into circle domain evaluations, bit-reversing row indices
    /// according to circle domain ordering.
    pub fn circle_evaluation<B>(
        &self,
    ) -> ColumnVec<CircleEvaluation<B, BaseField, BitReversedOrder>>
    where
        B: Backend,
    {
        self.traces.circle_evaluation()
    }

    #[doc(hidden)]
    /// Fills columns with values from BaseField slice.
    pub fn fill_program_columns_basefield(
        &mut self,
        row: usize,
        value: &[BaseField],
        col: ProgramColumn,
    ) {
        let n = value.len();
        assert_eq!(col.size(), n, "column size mismatch");
        for (i, b) in value.iter().enumerate() {
            self.traces.cols[col.offset() + i][row] = *b;
        }
    }

    #[doc(hidden)]
    /// Fills four columns with u32 value.
    fn fill_program_columns<const N: usize, T: IntoBaseFields<N>>(
        &mut self,
        row: usize,
        value: T,
        col: ProgramColumn,
    ) {
        let base_field_values = value.into_base_fields();
        self.fill_program_columns_basefield(row, &base_field_values, col);
    }

    /// Finds the row_idx from pc
    pub(crate) fn find_row_idx(&self, pc: u32) -> Option<usize> {
        if pc < self.pc_offset {
            return None;
        }
        let pc = pc - self.pc_offset;
        let pc = pc as usize;
        if pc % WORD_SIZE != 0 {
            return None;
        }
        let row_idx = pc / WORD_SIZE;
        if row_idx >= self.num_instructions {
            return None;
        }
        Some(row_idx)
    }
}
