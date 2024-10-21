use num_traits::Zero;
use stwo_prover::core::{backend::simd::m31::LOG_N_LANES, fields::m31::BaseField};

use super::column::Column;

pub mod eval;

use nexus_vm::cpu::RegisterFile;

// Program execution step.
pub(crate) struct Step {
    /// Machine registers.
    pub(crate) regs: RegisterFile,
    /// Program step.
    pub(crate) step: nexus_vm::trace::Step,
}

pub struct Traces(Vec<Vec<BaseField>>);

impl Traces {
    /// Returns [`Column::TOTAL_COLUMNS_NUM`] zeroed columns, each one `2.pow(log_size)` in length.
    pub fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self(vec![
            vec![BaseField::zero(); 1 << log_size];
            Column::COLUMNS_NUM
        ])
    }

    /// Returns inner representation of columns.
    pub fn into_inner(self) -> Vec<Vec<BaseField>> {
        self.0
    }

    /// Returns a copy of `N` raw columns in range `[offset..offset + N]` at `row`, where
    /// `N` is assumed to be equal `Column::size` of a `col`.
    #[doc(hidden)]
    pub fn column<const N: usize>(&self, row: usize, col: Column) -> [BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.0[offset..].iter();
        std::array::from_fn(|_idx| iter.next().expect("invalid offset; must be unreachable")[row])
    }

    /// Returns mutable reference to `N` raw columns in range `[offset..offset + N]` at `row`,
    /// where `N` is assumed to be equal `Column::size` of a `col`.
    #[doc(hidden)]
    pub fn column_mut<const N: usize>(&mut self, row: usize, col: Column) -> [&mut BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.0[offset..].iter_mut();
        std::array::from_fn(|_idx| {
            &mut iter.next().expect("invalid offset; must be unreachable")[row]
        })
    }
}

/// Returns a copy of `column` values as an array.
///
/// ```ignore
/// let mut traces = Traces::new(6);
/// let row = 0usize;
/// let mut add_row: [BaseField; 1] = trace_column!(traces, row, Column::IsAdd);
///
/// dbg!(add_row[0].is_one());
/// ```
macro_rules! trace_column {
    ($traces:expr, $row:expr, $col:expr) => {{
        $traces.column::<{ Column::size($col) }>($row, $col)
    }};
}

/// Returns a mutable reference to `column` values as an array.
///
/// ```ignore
/// let mut traces = Traces::new(6);
/// let row = 0usize;
/// let mut add_row: [&mut BaseField; 1] = trace_column_mut!(traces, row, Column::IsAdd);
///
/// *add_row[0] = BaseField::one();
/// ```
macro_rules! trace_column_mut {
    ($traces:expr, $row:expr, $col:expr) => {{
        $traces.column_mut::<{ Column::size($col) }>($row, $col)
    }};
}

pub(crate) use trace_column;
pub(crate) use trace_column_mut;
