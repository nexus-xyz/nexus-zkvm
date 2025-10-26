use num_traits::{One, Zero};
use stwo::{
    core::{fields::m31::BaseField, poly::circle::CanonicCoset, ColumnVec},
    prover::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};

use nexus_vm::WORD_SIZE;

use super::{utils::finalize_columns, TracesBuilder};
use crate::column::PreprocessedColumn;

/// Preprocessed (constant) traces builder corresponding to [`PreprocessedColumn`].
///
/// Should not be used outside of tests that require a subset of constant column, e.g. to bypass [`Self::MIN_LOG_SIZE`]
/// limitation.
pub(crate) struct PreprocessedBuilder(TracesBuilder);

impl PreprocessedBuilder {
    /// Min supported log size of the trace. This constant determines the size of the main component's trace.
    ///
    /// `LOG_N_LANES` trace size is not supported in the current prover configuration.
    pub const MIN_LOG_SIZE: u32 = 8;

    /// Returns [`PreprocessedColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length, filled with preprocessed trace content.
    fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        assert!(
            log_size >= Self::MIN_LOG_SIZE,
            "log_size must be at least {}",
            Self::MIN_LOG_SIZE,
        );
        let cols = vec![vec![BaseField::zero(); 1 << log_size]; PreprocessedColumn::COLUMNS_NUM];
        let mut ret = Self(TracesBuilder { cols, log_size });
        ret.fill_is_first();
        ret.fill_is_last();
        ret.fill_timestamps();
        ret
    }

    /// Returns the log_size of columns.
    pub fn log_size(&self) -> u32 {
        self.0.log_size
    }

    /// Returns the number of rows
    pub fn num_rows(&self) -> usize {
        self.0.num_rows()
    }

    fn fill_preprocessed_word(
        &mut self,
        row_idx: usize,
        preprocessed_column: PreprocessedColumn,
        clk: [u8; WORD_SIZE],
    ) {
        for (limb_idx, clk_byte) in clk.iter().enumerate() {
            self.0.cols[preprocessed_column.offset() + limb_idx][row_idx] =
                BaseField::from(*clk_byte as u32);
        }
    }

    pub(crate) fn fill_is_first(&mut self) {
        self.0.cols[PreprocessedColumn::IsFirst.offset()][0] = BaseField::one();
    }

    pub(crate) fn fill_is_last(&mut self) {
        *self.0.cols[PreprocessedColumn::IsLast.offset()]
            .last_mut()
            .expect("preprocessed trace must be non-empty") = BaseField::one();
    }

    pub(crate) fn fill_timestamps(&mut self) {
        // Make sure the last reg3_ts_cur computation doesn't overflow
        assert!(self.num_rows() < (u32::MAX as usize - 3) / 3);
        for row_idx in 0..(1 << self.log_size()) {
            let clk = (row_idx + 1) as u32;
            self.fill_preprocessed_word(row_idx, PreprocessedColumn::Clk, clk.to_le_bytes());
            let reg1_ts_cur = clk * 3 + 1;
            self.fill_preprocessed_word(
                row_idx,
                PreprocessedColumn::Reg1TsCur,
                reg1_ts_cur.to_le_bytes(),
            );
            let reg2_ts_cur = clk * 3 + 2;
            self.fill_preprocessed_word(
                row_idx,
                PreprocessedColumn::Reg2TsCur,
                reg2_ts_cur.to_le_bytes(),
            );
            let reg3_ts_cur = clk * 3 + 3;
            self.fill_preprocessed_word(
                row_idx,
                PreprocessedColumn::Reg3TsCur,
                reg3_ts_cur.to_le_bytes(),
            );
        }
    }

    pub(crate) fn finalize(self) -> PreprocessedTraces {
        let log_size = self.log_size();
        let cols = finalize_columns(self.0.cols);

        PreprocessedTraces { cols, log_size }
    }
}

/// Preprocessed (constant) traces corresponding to [`PreprocessedColumn`].
///
/// These columns are predefined and must not be altered during trace generation.
#[derive(Debug, Clone)]
pub struct PreprocessedTraces {
    cols: Vec<BaseColumn>,
    log_size: u32,
}

impl PreprocessedTraces {
    pub const MIN_LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;

    pub fn new(log_size: u32) -> Self {
        PreprocessedBuilder::new(log_size).finalize()
    }

    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    pub fn get_preprocessed_base_column<const N: usize>(
        &self,
        col: PreprocessedColumn,
    ) -> [&BaseColumn; N] {
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
