use eval::TraceEval;
use itertools::Itertools as _;
use num_traits::{One as _, Zero};
use stwo_prover::{
    constraint_framework::{assert_constraints, AssertEvaluator},
    core::{
        backend::{
            simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
            CpuBackend,
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
pub mod utils;

pub use program::{ProgramStep, Word, WordWithEffectiveBits};

use utils::{bit_reverse, coset_order_to_circle_domain_order};

pub struct Traces {
    cols: Vec<Vec<BaseField>>,
    log_size: u32,
}

impl Traces {
    /// Returns [`Column::TOTAL_COLUMNS_NUM`] zeroed columns, each one `2.pow(log_size)` in length.
    pub(crate) fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            cols: vec![vec![BaseField::zero(); 1 << log_size]; Column::COLUMNS_NUM],
            log_size,
        }
    }

    /// Returns [`Column::COLUMNS_NUM`] columns, each one `2.pow(log_size)` in length, filled with preprocessed trace content.
    pub(crate) fn new_preprocessed_trace(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        assert!(
            log_size >= 8,
            "log_size must be at least 8, to accomodate 256-element lookup tables"
        );
        let mut cols =
            vec![vec![BaseField::zero(); 1 << log_size]; PreprocessedColumn::COLUMNS_NUM];
        cols[PreprocessedColumn::IsFirst.offset()][0] = BaseField::one();
        for row_idx in 0..256 {
            cols[PreprocessedColumn::Range256.offset()][row_idx] = BaseField::from(row_idx);
        }
        Self { cols, log_size }
    }

    /// Returns inner representation of columns.
    pub fn into_inner(self) -> Vec<Vec<BaseField>> {
        self.cols
    }

    /// Returns a copy of `N` raw columns in range `[offset..offset + N]` at `row`, where
    /// `N` is assumed to be equal `Column::size` of a `col`.
    #[doc(hidden)]
    pub fn column<const N: usize>(&self, row: usize, col: Column) -> [BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.cols[offset..].iter();
        std::array::from_fn(|_idx| iter.next().expect("invalid offset; must be unreachable")[row])
    }

    /// Returns mutable reference to `N` raw columns in range `[offset..offset + N]` at `row`,
    /// where `N` is assumed to be equal `Column::size` of a `col`.
    #[doc(hidden)]
    pub fn column_mut<const N: usize>(&mut self, row: usize, col: Column) -> [&mut BaseField; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        let mut iter = self.cols[offset..].iter_mut();
        std::array::from_fn(|_idx| {
            &mut iter.next().expect("invalid offset; must be unreachable")[row]
        })
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

    /// Converts traces into circle domain evaluations, bit-reversing row indices
    /// according to circle domain ordering.
    pub fn into_circle_evaluation(
        self,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        self.cols
            .into_iter()
            .map(|col| {
                let mut eval = coset_order_to_circle_domain_order(col.as_slice());
                bit_reverse(&mut eval);

                let col = BaseColumn::from_iter(eval);
                CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, col)
            })
            .collect()
    }

    /// Converts traces into circle domain evaluations on CpuBackend
    ///
    /// This function is used during development for assertions. In production,
    /// use `into_circle_evaluation()` because stwo expects SimdBackend.
    pub fn into_cpu_circle_evaluation(
        self,
    ) -> ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        self.into_inner()
            .into_iter()
            .map(|eval| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, eval))
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
        let traces: Vec<CircleEvaluation<_, _, _>> = self.into_cpu_circle_evaluation();

        let preprocessed_trace =
            Traces::new_preprocessed_trace(log_size).into_cpu_circle_evaluation();

        let traces = TreeVec::new(vec![
            traces,
            vec![], /* interaction trace */
            preprocessed_trace,
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

pub(crate) use trace_column_mut;
