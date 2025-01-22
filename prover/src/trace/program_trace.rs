use num_traits::Zero;

use stwo_prover::core::{
    backend::{
        simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        Column,
    },
    fields::m31::BaseField,
    poly::{
        circle::{CanonicCoset, CircleEvaluation},
        BitReversedOrder,
    },
    ColumnVec,
};

use super::{utils::finalize_columns, IntoBaseFields, TracesBuilder};
use crate::column::ProgramColumn;

use nexus_vm::{
    emulator::{ProgramInfo, ProgramMemoryEntry},
    WORD_SIZE,
};

/// Warapper around [`TracesBuilder`] that contains the program layout for figuring out the row_idx out of pc.
pub struct ProgramTracesBuilder {
    traces_builder: TracesBuilder,
    /// Program counter written on the first row. The current assumption is that the program is in contiguous memory starting from [`Self::pc_offset`].
    /// This value is used by the program memory checking when it computes the row index corresponding to a pc value.
    pc_offset: u32,
    num_instructions: usize,
}

impl ProgramTracesBuilder {
    pub fn dummy(log_size: u32) -> Self {
        Self::new(log_size, ProgramInfo::dummy())
    }

    /// Returns [`ProgramColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length, filled with program content.
    pub fn new(
        log_size: u32,
        program: ProgramInfo<impl IntoIterator<Item = ProgramMemoryEntry>>,
    ) -> Self {
        assert!(log_size >= LOG_N_LANES);
        let mut cols = vec![vec![BaseField::zero(); 1 << log_size]; ProgramColumn::COLUMNS_NUM];
        let mut pc_offset = 0u32;
        let mut num_instructions = 0usize;

        Self::fill_program_columns(
            &mut cols,
            0,
            program.initial_pc,
            ProgramColumn::PrgInitialPc,
        );
        for (
            row_idx,
            ProgramMemoryEntry {
                pc,
                instruction_word,
            },
        ) in program.program.into_iter().enumerate()
        {
            if row_idx == 0 {
                pc_offset = pc;
            }
            num_instructions += 1;
            assert_eq!(
                row_idx * WORD_SIZE + pc_offset as usize,
                pc as usize,
                "The program is assumed to be in contiguous memory."
            );
            Self::fill_program_columns(&mut cols, row_idx, pc, ProgramColumn::PrgMemoryPc);
            Self::fill_program_columns(
                &mut cols,
                row_idx,
                instruction_word,
                ProgramColumn::PrgMemoryWord,
            );
            Self::fill_program_columns(&mut cols, row_idx, true, ProgramColumn::PrgMemoryFlag);
        }
        Self {
            traces_builder: TracesBuilder { cols, log_size },
            pc_offset,
            num_instructions,
        }
    }

    #[doc(hidden)]
    /// Fills columns with values from BaseField slice.
    fn fill_program_columns_base_field(
        cols: &mut [Vec<BaseField>],
        row: usize,
        value: &[BaseField],
        col: ProgramColumn,
    ) {
        let n = value.len();
        assert_eq!(col.size(), n, "column size mismatch");
        for (i, b) in value.iter().enumerate() {
            cols[col.offset() + i][row] = *b;
        }
    }

    /// Fills four columns with values that can be turned into BaseField elements.
    pub(crate) fn fill_program_columns<const N: usize, T: IntoBaseFields<N>>(
        cols: &mut [Vec<BaseField>],
        row: usize,
        value: T,
        col: ProgramColumn,
    ) {
        let base_field_values = value.into_base_fields();
        Self::fill_program_columns_base_field(cols, row, &base_field_values, col);
    }

    /// Finalize the building and produce ProgramTraces.
    pub fn finalize(self) -> ProgramTraces {
        ProgramTraces {
            cols: finalize_columns(self.traces_builder.cols),
            log_size: self.traces_builder.log_size,
        }
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

    pub(crate) fn column<const N: usize>(&self, row: usize, col: ProgramColumn) -> [BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.traces_builder.cols[offset..].iter();
        std::array::from_fn(|_idx| {
            iter.next()
                .expect("invalid offset; must be unreachable")
                .at(row)
        })
    }
}

/// Program (constant) trace containing [`ProgramColumn`].
///
/// These columns contain the whole program and the first program counter. They don't depend on the runtime information.
/// Moreover, the public input and output are included in the program trace. These depend on the runtime information.
/// The commitment to the program trace will be checked by the verifier.
#[derive(Debug, Clone)]
pub struct ProgramTraces {
    cols: Vec<BaseColumn>,
    log_size: u32,
}

impl ProgramTraces {
    /// Returns the log_size of columns.
    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Returns reference to `N` raw columns in range `[offset..offset + N]` in the bit-reversed BaseColumn format.
    ///
    /// This function allows SIMD-aware stwo libraries (for instance, logup) to read columns in the format they expect.
    pub fn get_base_column<const N: usize>(&self, col: ProgramColumn) -> [&BaseColumn; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        std::array::from_fn(|i| &self.cols[col.offset() + i])
    }

    pub fn into_circle_evaluation(
        self,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        self.cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }
}
