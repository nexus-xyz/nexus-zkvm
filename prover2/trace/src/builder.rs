use std::marker::PhantomData;

use num_traits::Zero;
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES},
    fields::m31::BaseField,
};

use nexus_common::constants::WORD_SIZE;
use nexus_vm_prover_air_column::AirColumn;

use super::utils::{self, IntoBaseFields};

/// Wrapper struct for generating and indexing AIR traces.
///
/// Values are stored in original (coset) order.
#[derive(Debug, Clone)]
pub struct TraceBuilder<C> {
    pub cols: Vec<Vec<BaseField>>,
    pub log_size: u32,
    phantom_data: PhantomData<C>,
}

impl<C: AirColumn> TraceBuilder<C> {
    /// Returns `C::COLUMNS_NUM` zeroed columns, each one `2.pow(log_size)` in length.
    pub fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            cols: vec![vec![BaseField::zero(); 1 << log_size]; C::COLUMNS_NUM],
            log_size,
            phantom_data: PhantomData,
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
    pub fn column<const N: usize>(&self, row: usize, col: C) -> [BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.cols[offset..].iter();
        std::array::from_fn(|_idx| iter.next().expect("invalid offset; must be unreachable")[row])
    }

    /// Returns mutable reference to `N` raw columns in range `[offset..offset + N]` at `row`,
    /// where `N` is assumed to be equal `Column::size` of a `col`.
    pub fn column_mut<const N: usize>(&mut self, row: usize, col: C) -> [&mut BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.cols[offset..].iter_mut();
        std::array::from_fn(|_idx| {
            &mut iter.next().expect("invalid offset; must be unreachable")[row]
        })
    }

    /// Fills four columns with u32 value.
    pub fn fill_columns<const N: usize, T: IntoBaseFields<N>>(
        &mut self,
        row: usize,
        value: T,
        col: C,
    ) {
        let base_field_values = value.into_base_fields();
        self.fill_columns_base_field(row, &base_field_values, col);
    }

    /// Fills columns with values from a byte slice.
    pub fn fill_columns_bytes(&mut self, row: usize, value: &[u8], col: C) {
        let base_field_values: Vec<BaseField> =
            value.iter().map(|b| BaseField::from(*b as u32)).collect();
        self.fill_columns_base_field(row, base_field_values.as_slice(), col);
    }

    /// Fills columns with values from BaseField slice.
    pub fn fill_columns_base_field(&mut self, row: usize, value: &[BaseField], col: C) {
        let n = value.len();
        assert_eq!(col.size(), n, "column size mismatch");
        for (i, b) in value.iter().enumerate() {
            self.cols[col.offset() + i][row] = *b;
        }
    }

    /// Fills columns with values from a byte slice, applying a selector.
    ///
    /// If the selector is true, fills the columns with values from the byte slice. Otherwise, fills with zeros.
    pub fn fill_effective_columns(&mut self, row: usize, src: C, dst: C, selector: C) {
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
    pub fn finalize(self) -> FinalizedTrace {
        let cols = self.cols.into_iter().map(BaseColumn::from_iter).collect();
        FinalizedTrace {
            cols,
            log_size: self.log_size,
        }
    }

    /// Bit-reverse rows and finalize trace.
    ///
    /// Should be used when the circuit requires cross-row constraints.
    pub fn finalize_bit_reversed(self) -> FinalizedTrace {
        let cols = utils::finalize_columns(self.cols);
        FinalizedTrace {
            cols,
            log_size: self.log_size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FinalizedTrace {
    pub cols: Vec<BaseColumn>,
    pub log_size: u32,
}

impl FinalizedTrace {
    pub fn empty() -> Self {
        Self {
            cols: Vec::new(),
            log_size: 0,
        }
    }
}
