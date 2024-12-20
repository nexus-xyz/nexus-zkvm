use num_traits::{One, Zero};
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
    fields::m31::BaseField,
    poly::{
        circle::{CanonicCoset, CircleEvaluation},
        BitReversedOrder,
    },
    ColumnVec,
};

use nexus_common::riscv::register::NUM_REGISTERS;
use nexus_vm::WORD_SIZE;

use super::{utils::finalize_columns, TracesBuilder};
use crate::column::PreprocessedColumn;

/// Preprocessed (constant) traces builder corresponding to [`PreprocessedColumn`].
///
/// Should not be used outside of tests that require a subset of constant column, e.g. to bypass [`Self::MIN_LOG_SIZE`]
/// limitation.
pub(crate) struct PreprocessedBuilder(TracesBuilder);

impl PreprocessedBuilder {
    /// 2^MIN_LOG_SIZE is the smallest number of rows supported
    ///
    /// 2^16 rows are needed to accommodate (byte, byte) lookup tables
    pub const MIN_LOG_SIZE: u32 = 16;

    /// Returns [`PreprocessedColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length, filled with preprocessed trace content.
    fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        assert!(
            log_size >= Self::MIN_LOG_SIZE,
            "log_size must be at least {}, to accomodate (byte, byte) lookup tables",
            Self::MIN_LOG_SIZE,
        );
        let cols = vec![vec![BaseField::zero(); 1 << log_size]; PreprocessedColumn::COLUMNS_NUM];
        let mut ret = Self(TracesBuilder { cols, log_size });
        ret.fill_is_first();
        ret.fill_row_idx();
        ret.fill_is_first32();
        ret.fill_timestamps();
        ret.fill_range1024();
        ret.fill_range256();
        ret.fill_range128();
        ret.fill_range32();
        ret.fill_range8();
        ret.fill_range16();
        ret.fill_bitwise();
        ret
    }

    /// Returns [`PreprocessedColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length
    ///
    /// Only for tests that create custom preprocessed trace.
    #[cfg(test)]
    pub(crate) fn empty(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        let cols = vec![vec![BaseField::zero(); 1 << log_size]; PreprocessedColumn::COLUMNS_NUM];
        Self(TracesBuilder { cols, log_size })
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
        for (limb_idx, clk_byte) in clk.iter().enumerate().take(WORD_SIZE) {
            self.0.cols[preprocessed_column.offset() + limb_idx][row_idx] =
                BaseField::from(*clk_byte as u32);
        }
    }

    pub(crate) fn fill_is_first(&mut self) {
        self.0.cols[PreprocessedColumn::IsFirst.offset()][0] = BaseField::one();
    }

    pub(crate) fn fill_row_idx(&mut self) {
        assert!(self.log_size() < 31);
        for row_idx in 0..self.num_rows() {
            self.0.cols[PreprocessedColumn::RowIdx.offset()][row_idx] = BaseField::from(row_idx);
        }
    }

    pub(crate) fn fill_is_first32(&mut self) {
        assert_eq!(NUM_REGISTERS, 32);
        for row_idx in 0..32 {
            self.0.cols[PreprocessedColumn::IsFirst32.offset()][row_idx] = BaseField::one();
        }
    }

    pub(crate) fn fill_range256(&mut self) {
        for row_idx in 0..256 {
            self.0.cols[PreprocessedColumn::Range256.offset()][row_idx] = BaseField::from(row_idx);
        }
    }

    pub(crate) fn fill_range32(&mut self) {
        for row_idx in 0..32 {
            self.0.cols[PreprocessedColumn::Range32.offset()][row_idx] = BaseField::from(row_idx);
        }
    }

    pub(crate) fn fill_range128(&mut self) {
        for row_idx in 0..128 {
            self.0.cols[PreprocessedColumn::Range128.offset()][row_idx] = BaseField::from(row_idx);
        }
    }

    fn fill_range8(&mut self) {
        for row_idx in 0..8 {
            self.0.cols[PreprocessedColumn::Range8.offset()][row_idx] = BaseField::from(row_idx);
        }
    }

    pub(crate) fn fill_range16(&mut self) {
        for row_idx in 0..16 {
            self.0.cols[PreprocessedColumn::Range16.offset()][row_idx] = BaseField::from(row_idx);
        }
    }

    fn fill_range1024(&mut self) {
        for row_idx in 0..1024 {
            self.0.cols[PreprocessedColumn::Range1024.offset()][row_idx] = BaseField::from(row_idx);
        }
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

    fn fill_bitwise(&mut self) {
        let cols = &mut self.0.cols;
        // fill bit-wise lookup table
        for input_b in 0..=255u8 {
            for input_c in 0..=255u8 {
                let row_idx = (input_b as usize) << 8 | input_c as usize;
                cols[PreprocessedColumn::BitwiseByteB.offset()][row_idx] =
                    BaseField::from(input_b as u32);
                cols[PreprocessedColumn::BitwiseByteC.offset()][row_idx] =
                    BaseField::from(input_c as u32);
                cols[PreprocessedColumn::BitwiseAndByteA.offset()][row_idx] =
                    BaseField::from((input_b & input_c) as u32);
                cols[PreprocessedColumn::BitwiseOrByteA.offset()][row_idx] =
                    BaseField::from((input_b | input_c) as u32);
                cols[PreprocessedColumn::BitwiseXorByteA.offset()][row_idx] =
                    BaseField::from((input_b ^ input_c) as u32);
            }
        }
        // Notice, (0, 0, 0) is a valid entry for XOR, AND and OR. A malicious prover can use these entries; that's fine.
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
