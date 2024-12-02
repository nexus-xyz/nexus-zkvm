use eval::TraceEval;
use itertools::Itertools;
use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{assert_constraints, AssertEvaluator},
    core::{
        backend::{
            simd::{column::BaseColumn, m31::LOG_N_LANES},
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

use super::column::Column;

pub mod eval;
pub mod preprocessed;
pub mod program;
pub mod regs;
pub mod sidenote;
pub mod utils;

pub use preprocessed::PreprocessedTraces;
pub use program::{BoolWord, ProgramStep, Word, WordWithEffectiveBits};

use utils::{bit_reverse, coset_order_to_circle_domain_order, IntoBaseFields};

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

        let preprocessed_trace = PreprocessedTraces::new(log_size).circle_evaluation();

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
