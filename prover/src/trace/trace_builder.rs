use itertools::Itertools;
use nexus_vm::WORD_SIZE;
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

use super::utils::{finalize_columns, IntoBaseFields};
use crate::column::Column;

/// Main ([`stwo_prover::constraint_framework::ORIGINAL_TRACE_IDX`]) trace builder which implements
/// mutable access to columns.
///
/// Values are stored in original (coset) order.
#[derive(Debug, Clone)]
pub struct TracesBuilder {
    pub cols: Vec<Vec<BaseField>>,
    pub log_size: u32,
}

impl TracesBuilder {
    /// Returns [`Column::TOTAL_COLUMNS_NUM`] zeroed columns, each one `2.pow(log_size)` in length.
    pub fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            cols: vec![vec![BaseField::zero(); 1 << log_size]; Column::COLUMNS_NUM],
            log_size,
        }
    }

    /// Returns inner representation of columns.
    pub fn into_inner(self) -> Vec<Vec<BaseField>> {
        self.cols
    }

    /// Returns the log_size of columns.
    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Returns the number of rows
    pub fn num_rows(&self) -> usize {
        1 << self.log_size
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
        self.fill_columns_base_field(row, &base_field_values, col);
    }

    /// Fills columns with values from a byte slice.
    pub fn fill_columns_bytes(&mut self, row: usize, value: &[u8], col: Column) {
        let base_field_values = value
            .iter()
            .map(|b| BaseField::from(*b as u32))
            .collect_vec();
        self.fill_columns_base_field(row, base_field_values.as_slice(), col);
    }

    /// Fills columns with values from BaseField slice.
    pub fn fill_columns_base_field(&mut self, row: usize, value: &[BaseField], col: Column) {
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
        src: Column,
        dst: Column,
        selector: Column,
    ) {
        let src_len = src.size();
        let dst_len = dst.size();
        assert_eq!(src_len, dst_len, "column size mismatch");
        let src: [_; WORD_SIZE] = self.column(row, src);
        let [sel] = self.column(row, selector);
        let dst: [_; WORD_SIZE] = self.column_mut(row, dst);
        if sel.is_zero() {
            for dst_limb in dst.into_iter() {
                *dst_limb = BaseField::zero();
            }
        } else {
            for i in 0..dst_len {
                *dst[i] = src[i];
            }
        }
    }

    /// Finalize trace and convert raw columns to [`BaseColumn`].
    pub fn finalize(self) -> FinalizedTraces {
        let cols = finalize_columns(self.cols);

        FinalizedTraces {
            cols,
            log_size: self.log_size,
        }
    }
}

/// Finalized main trace that stores columns in (bit reversed) circle domain order.
#[derive(Debug, Clone)]
pub struct FinalizedTraces {
    cols: Vec<BaseColumn>,
    log_size: u32,
}

impl FinalizedTraces {
    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    pub fn get_base_column<const N: usize>(&self, col: Column) -> [&BaseColumn; N] {
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
