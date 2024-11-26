use std::array;

use eval::TraceEval;
use itertools::Itertools as _;
use nexus_vm::WORD_SIZE;
use num_traits::{One as _, Zero};
use stwo_prover::{
    constraint_framework::{assert_constraints, AssertEvaluator},
    core::{
        backend::{
            simd::{bit_reverse::MIN_LOG_SIZE, column::BaseColumn, m31::LOG_N_LANES},
            Backend, CpuBackend,
        },
        fields::m31::BaseField,
        pcs::TreeVec,
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use crate::machine2::column::PreprocessedColumn;

use super::column::Column;

pub mod eval;
pub mod program;
pub mod regs;
pub mod utils;

pub use program::{BoolWord, ProgramStep, Word, WordWithEffectiveBits};

use utils::{bit_reverse, coset_order_to_circle_domain_order};

pub struct Traces {
    cols: Vec<Vec<BaseField>>,
    log_size: u32,
}

/// Trait for BaseField representation
pub(crate) trait IntoBaseFields<const N: usize> {
    fn into_base_fields(self) -> [BaseField; N];
}

impl IntoBaseFields<1> for bool {
    fn into_base_fields(self) -> [BaseField; 1] {
        [BaseField::from(self as u32)]
    }
}

impl IntoBaseFields<1> for u8 {
    fn into_base_fields(self) -> [BaseField; 1] {
        [BaseField::from(self as u32)]
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for [bool; WORD_SIZE] {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        std::array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for Word {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for WordWithEffectiveBits {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        self.0.into_base_fields()
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for u32 {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        let bytes = self.to_le_bytes();
        array::from_fn(|i| BaseField::from(bytes[i] as u32))
    }
}

/// Trait for reading Basefields
pub(crate) trait FromBaseFields<const N: usize> {
    fn from_base_fields(elms: [BaseField; N]) -> Self;
}

impl FromBaseFields<WORD_SIZE> for Word {
    fn from_base_fields(elms: [BaseField; WORD_SIZE]) -> Self {
        let mut ret = Word::default();
        for (i, b) in elms.iter().enumerate() {
            let read = b.0;
            assert!(read < 256, "invalid byte value");
            ret[i] = read as u8;
        }
        ret
    }
}

impl FromBaseFields<WORD_SIZE> for u32 {
    fn from_base_fields(elms: [BaseField; WORD_SIZE]) -> Self {
        let bytes = Word::from_base_fields(elms);
        u32::from_le_bytes(bytes)
    }
}

impl Traces {
    /// 2^MIN_LOG_SIZE is the smallest number of rows supported
    ///
    /// 2^16 rows are needed to accommodate (byte, byte) lookup tables
    pub const MIN_LOG_SIZE: u32 = 16;
    /// Returns [`Column::TOTAL_COLUMNS_NUM`] zeroed columns, each one `2.pow(log_size)` in length.
    pub(crate) fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            cols: vec![vec![BaseField::zero(); 1 << log_size]; Column::COLUMNS_NUM],
            log_size,
        }
    }

    /// Returns [`PreprocessedColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length, filled with preprocessed trace content.
    pub(crate) fn new_preprocessed_trace(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        assert!(
            log_size >= MIN_LOG_SIZE,
            "log_size must be at least {}, to accomodate (byte, byte) lookup tables",
            MIN_LOG_SIZE,
        );
        let cols = vec![vec![BaseField::zero(); 1 << log_size]; PreprocessedColumn::COLUMNS_NUM];
        let mut ret = Self { cols, log_size };
        ret.fill_is_first();
        ret.fill_timestamps();
        ret.fill_range256();
        ret.fill_range32();
        ret.fill_bitwise();
        ret
    }

    /// Returns [`PreprocessedColumn::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length
    ///
    /// Only for tests that create custome preprocessed trace.
    #[cfg(test)]
    pub(crate) fn empty_preprocessed_trace(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        let cols = vec![vec![BaseField::zero(); 1 << log_size]; PreprocessedColumn::COLUMNS_NUM];
        Self { cols, log_size }
    }

    /// Returns inner representation of columns.
    pub fn into_inner(self) -> Vec<Vec<BaseField>> {
        self.cols
    }

    /// Returns the log_size of columns.
    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Returns a copy of `N` raw columns in range `[offset..offset + N]` at `row`, where
    /// `N` is assumed to be equal `Column::size` of a `col`.
    pub fn column<const N: usize>(&self, row: usize, col: Column) -> [BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.cols[offset..].iter();
        std::array::from_fn(|_idx| iter.next().expect("invalid offset; must be unreachable")[row])
    }

    /// Returns mutable reference to `N` raw columns in range `[offset..offset + N]` at `row`,
    /// where `N` is assumed to be equal `Column::size` of a `col`.
    pub fn column_mut<const N: usize>(&mut self, row: usize, col: Column) -> [&mut BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.cols[offset..].iter_mut();
        std::array::from_fn(|_idx| {
            &mut iter.next().expect("invalid offset; must be unreachable")[row]
        })
    }

    /// Fills four columns with u32 value.
    pub(crate) fn fill_columns<const N: usize, T: IntoBaseFields<N>>(
        &mut self,
        row: usize,
        value: T,
        col: Column,
    ) {
        let base_field_values = value.into_base_fields();
        self.fill_columns_basefield(row, &base_field_values, col);
    }

    /// Fills columns with values from a byte slice.
    pub fn fill_columns_bytes(&mut self, row: usize, value: &[u8], col: Column) {
        let base_field_values = value
            .iter()
            .map(|b| BaseField::from(*b as u32))
            .collect_vec();
        self.fill_columns_basefield(row, base_field_values.as_slice(), col);
    }

    /// Fills columns with values from BaseField slice.
    pub fn fill_columns_basefield(&mut self, row: usize, value: &[BaseField], col: Column) {
        let n = value.len();
        assert_eq!(col.size(), n, "column size mismatch");
        for (i, b) in value.iter().enumerate() {
            self.cols[col.offset() + i][row] = *b;
        }
    }

    /// Fills columns with values from a byte slice, applying a selector.
    ///
    /// If the selector is true, fills the columns with values from the byte slice. Otherwise, fills with zeros.
    pub fn fill_effective_columns(
        &mut self,
        row: usize,
        value: &[u8],
        col: Column,
        selector: bool,
    ) {
        let n = value.len();
        assert_eq!(col.size(), n, "column size mismatch");
        for (i, b) in value.iter().enumerate() {
            self.cols[col.offset() + i][row] = if selector {
                BaseField::from(*b as u32)
            } else {
                BaseField::zero()
            };
        }
    }

    /// Returns a copy of `N` raw columns in range `[offset..offset + N]` in the bit-reversed BaseColumn format.
    ///
    /// This function allows SIMD-aware stwo libraries (for instance, logup) to read columns in the format they expect.
    pub fn get_base_column<const N: usize>(&self, col: Column) -> [BaseColumn; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        self.cols[col.offset()..]
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

    /// Returns a copy of `N` raw columns in range `[offset..offset + N]` in the bit-reversed BaseColumn format.
    ///
    /// This function allows SIMD-aware stwo libraries (for instance, logup) to read columns in the format they expect.
    /// It's desirable to merge this function with get_base_column() by turning PreprocessedColumn into a type-parameter,
    /// but that requires a Rust experimental feature called `const_trait_impl`. We avoid Rust experimental features.
    pub fn get_preprocessed_base_column<const N: usize>(
        &self,
        col: PreprocessedColumn,
    ) -> [BaseColumn; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        self.cols[col.offset()..]
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

    /// Converts traces into circle domain evaluations, bit-reversing row indices
    /// according to circle domain ordering.
    pub fn circle_evaluation<B>(
        &self,
    ) -> ColumnVec<CircleEvaluation<B, BaseField, BitReversedOrder>>
    where
        B: Backend,
    {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        self.cols
            .iter()
            .map(|col| {
                let mut eval = coset_order_to_circle_domain_order(col.as_slice());
                bit_reverse(&mut eval);

                CircleEvaluation::<B, _, BitReversedOrder>::new(domain, eval.into_iter().collect())
            })
            .collect()
    }
    /// Asserts add_constraints_calls() in a main trace
    ///
    /// This function combines the trace with an empty preprocessed-trace and
    /// an empty interaction trace and then calls `add_constraints_calls()` on
    /// the combination. This is useful in test cases.
    pub fn assert_as_original_trace<F>(self, add_constraints_calls: F)
    where
        F: for<'a, 'b, 'c> Fn(&'a mut AssertEvaluator<'c>, &'b TraceEval<AssertEvaluator<'c>>),
    {
        let log_size = self.log_size;
        // Convert traces to the format expected by assert_constraints
        let traces: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> =
            self.circle_evaluation();

        let preprocessed_trace = Traces::new_preprocessed_trace(log_size).circle_evaluation();

        let traces = TreeVec::new(vec![
            preprocessed_trace,
            traces,
            vec![], /* interaction trace */
        ]);
        let trace_polys = traces.map(|trace| {
            trace
                .into_iter()
                .map(|c| c.interpolate())
                .collect::<Vec<_>>()
        });

        // Now check the constraints to make sure they're satisfied
        assert_constraints(&trace_polys, CanonicCoset::new(log_size), |mut eval| {
            let trace_eval = TraceEval::new(&mut eval);
            add_constraints_calls(&mut eval, &trace_eval);
        });
    }
}

impl Traces {
    fn fill_preprocessed_word(
        &mut self,
        row_idx: usize,
        preprocessed_column: PreprocessedColumn,
        clk: [u8; WORD_SIZE],
    ) {
        for (limb_idx, clk_byte) in clk.iter().enumerate().take(WORD_SIZE) {
            self.cols[preprocessed_column.offset() + limb_idx][row_idx] =
                BaseField::from(*clk_byte as u32);
        }
    }
    pub(crate) fn fill_is_first(&mut self) {
        self.cols[PreprocessedColumn::IsFirst.offset()][0] = BaseField::one();
    }
    pub(crate) fn fill_range256(&mut self) {
        for row_idx in 0..256 {
            self.cols[PreprocessedColumn::Range256.offset()][row_idx] = BaseField::from(row_idx);
        }
    }
    fn fill_range32(&mut self) {
        for row_idx in 0..32 {
            self.cols[PreprocessedColumn::Range32.offset()][row_idx] = BaseField::from(row_idx);
        }
    }
    fn fill_timestamps(&mut self) {
        // Make sure the last reg3_ts_cur computation doesn't overflow
        debug_assert!(1 << self.log_size < (u32::MAX - 3) / 3);
        for row_idx in 0..(1 << self.log_size) {
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
        // fill bit-wise lookup table
        for input_b in 0..=255u8 {
            for input_c in 0..=255u8 {
                let row_idx = (input_b as usize) << 8 | input_c as usize;
                self.cols[PreprocessedColumn::BitwiseByteB.offset()][row_idx] =
                    BaseField::from(input_b as u32);
                self.cols[PreprocessedColumn::BitwiseByteC.offset()][row_idx] =
                    BaseField::from(input_c as u32);
                self.cols[PreprocessedColumn::BitwiseAndByteA.offset()][row_idx] =
                    BaseField::from((input_b & input_c) as u32);
                self.cols[PreprocessedColumn::BitwiseOrByteA.offset()][row_idx] =
                    BaseField::from((input_b | input_c) as u32);
                self.cols[PreprocessedColumn::BitwiseXorByteA.offset()][row_idx] =
                    BaseField::from((input_b ^ input_c) as u32);
            }
        }
        // Notice, (0, 0, 0) is a valid entry for XOR, AND and OR. A malicious prover can use these entries; that's fine.
    }
}
