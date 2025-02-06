use num_traits::Zero;
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
    fields::m31::BaseField,
    poly::{
        circle::{CanonicCoset, CircleEvaluation},
        BitReversedOrder,
    },
    ColumnVec,
};

use super::{
    utils::{finalize_columns, IntoBaseFields},
    TracesBuilder,
};
use crate::column::ProgramColumn;

use nexus_vm::{
    emulator::{MemoryInitializationEntry, ProgramInfo, ProgramMemoryEntry, PublicOutputEntry},
    WORD_SIZE,
};

/// Wrapper around [`TracesBuilder`] that contains the program layout for figuring out the row_idx out of pc.
pub struct ProgramTracesBuilder {
    traces_builder: TracesBuilder,
    /// Program counter written on the first row. The current assumption is that the program is in contiguous memory starting from [`Self::pc_offset`].
    /// This value is used by the program memory checking when it computes the row index corresponding to a pc value.
    pub(crate) pc_offset: u32,
    pub(crate) num_instructions: usize,
}

impl ProgramTracesBuilder {
    pub fn new(
        log_size: u32,
        program_memory: &ProgramInfo,
        init_memory: &[MemoryInitializationEntry],
        exit_code: &[PublicOutputEntry],
        output_memory: &[PublicOutputEntry],
    ) -> Self {
        assert!(log_size >= LOG_N_LANES);
        assert!(
            program_memory.program.len() <= 1 << log_size,
            "Program is longer than program trace size"
        );
        assert!(init_memory.len() + exit_code.len() + output_memory.len() <= 1 << log_size);

        let cols = vec![vec![BaseField::zero(); 1 << log_size]; ProgramColumn::COLUMNS_NUM];
        let builder = TracesBuilder { cols, log_size };
        let mut ret = Self {
            traces_builder: builder,
            pc_offset: 0u32,
            num_instructions: 0usize,
        };

        ret.fill_program_columns(0, program_memory.initial_pc, ProgramColumn::PrgInitialPc);
        for (
            row_idx,
            ProgramMemoryEntry {
                pc,
                instruction_word,
            },
        ) in program_memory.program.iter().enumerate()
        {
            if row_idx == 0 {
                ret.pc_offset = *pc;
            }
            ret.num_instructions += 1;
            assert_eq!(
                row_idx * WORD_SIZE + ret.pc_offset as usize,
                *pc as usize,
                "The program is assumed to be in contiguous memory."
            );
            ret.fill_program_columns(row_idx, *pc, ProgramColumn::PrgMemoryPc);
            ret.fill_program_columns(row_idx, *instruction_word, ProgramColumn::PrgMemoryWord);
            ret.fill_program_columns(row_idx, true, ProgramColumn::PrgMemoryFlag);
        }

        let init_memory_len = init_memory.len();
        let exit_code_len = exit_code.len();

        for (row_idx, MemoryInitializationEntry { address, value }) in
            init_memory.iter().enumerate()
        {
            ret.fill_program_columns(row_idx, *address, ProgramColumn::PublicInputOutputAddr);

            ret.fill_program_columns(row_idx, true, ProgramColumn::PublicInputFlag);
            ret.fill_program_columns(row_idx, *value, ProgramColumn::PublicInputValue);
        }
        let offset = init_memory_len;

        for (_row_idx, PublicOutputEntry { .. }) in exit_code.iter().enumerate() {
            // TODO: handle exit code as a public output
            // let row_idx = row_idx + offset;
            // ret.fill_program_columns(row_idx, *address, ProgramColumn::PublicInputOutputAddr);

            // ret.fill_program_columns(row_idx, true, ProgramColumn::PublicOutputFlag);
            // ret.fill_program_columns(row_idx, *value, ProgramColumn::PublicOutputValue);
        }
        let offset = offset + exit_code_len;
        for (row_idx, PublicOutputEntry { address, value }) in output_memory.iter().enumerate() {
            let row_idx = row_idx + offset;
            ret.fill_program_columns(row_idx, *address, ProgramColumn::PublicInputOutputAddr);

            ret.fill_program_columns(row_idx, true, ProgramColumn::PublicOutputFlag);
            ret.fill_program_columns(row_idx, *value, ProgramColumn::PublicOutputValue);
        }
        ret
    }

    #[cfg(test)]
    pub(crate) fn new_with_empty_memory(log_size: u32, program_memory: &ProgramInfo) -> Self {
        Self::new(log_size, program_memory, &[], &[], &[])
    }

    #[cfg(test)]
    pub(crate) fn dummy(log_size: u32) -> Self {
        Self::new_with_empty_memory(log_size, &ProgramInfo::dummy())
    }

    #[doc(hidden)]
    /// Fills columns with values from BaseField slice.
    fn fill_program_columns_base_field(
        &mut self,
        row: usize,
        value: &[BaseField],
        col: ProgramColumn,
    ) {
        let n = value.len();
        assert_eq!(col.size(), n, "column size mismatch");
        for (i, b) in value.iter().enumerate() {
            self.traces_builder.cols[col.offset() + i][row] = *b;
        }
    }

    /// Fills four columns with values that can be turned into BaseField elements.
    pub(crate) fn fill_program_columns<const N: usize, T: IntoBaseFields<N>>(
        &mut self,
        row: usize,
        value: T,
        col: ProgramColumn,
    ) {
        let base_field_values = value.into_base_fields();
        self.fill_program_columns_base_field(row, &base_field_values, col);
    }

    /// Finalize the building and produce ProgramTraces.
    pub fn finalize(self) -> ProgramTraces {
        ProgramTraces {
            cols: finalize_columns(self.traces_builder.cols),
            log_size: self.traces_builder.log_size,
        }
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
