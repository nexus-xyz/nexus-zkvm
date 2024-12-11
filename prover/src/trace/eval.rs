use std::array;

use stwo_prover::constraint_framework::{EvalAtRow, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use crate::column::{Column, PreprocessedColumn};

// Trace evaluation at the current row and the next row.
pub struct TraceEval<E: EvalAtRow> {
    evals: Vec<[E::F; 2]>,
    preprocessed_evals: Vec<[E::F; 2]>,
}

impl<E: EvalAtRow> TraceEval<E> {
    pub(crate) fn new(eval: &mut E) -> Self {
        let evals =
            std::iter::repeat_with(|| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]))
                .take(Column::COLUMNS_NUM)
                .collect();
        let preprocessed_evals =
            std::iter::repeat_with(|| eval.next_interaction_mask(PREPROCESSED_TRACE_IDX, [0, 1]))
                .take(PreprocessedColumn::COLUMNS_NUM)
                .collect();
        Self {
            evals,
            preprocessed_evals,
        }
    }

    #[doc(hidden)]
    pub fn column_eval<const N: usize>(&self, col: Column) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();

        array::from_fn(|i| self.evals[offset + i][0].clone())
    }

    #[doc(hidden)]
    pub fn column_eval_next_row<const N: usize>(&self, col: Column) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();

        array::from_fn(|i| self.evals[offset + i][1].clone())
    }

    #[doc(hidden)]
    pub fn preprocessed_column_eval<const N: usize>(
        &self,
        col: PreprocessedColumn,
    ) -> ([E::F; N], [E::F; N]) {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();

        (
            array::from_fn(|i| self.preprocessed_evals[offset + i][0].clone()),
            array::from_fn(|i| self.preprocessed_evals[offset + i][1].clone()),
        )
    }
}

/// Returns evaluations for a given column.
///
/// ```ignore
/// let trace_eval = TraceEval::new(&mut eval);
/// let curr = trace_eval!(trace_eval, Column::IsAdd);
/// eval.add_constraint(curr[0]);
/// ```
macro_rules! trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval::<{ Column::size($col) }>($col)
    }};
}

pub(crate) use trace_eval;

/// Returns evaluations for a given column on the next row.
///
/// ```ignore
/// let trace_eval_next_row = TraceEval::new(&mut eval);
/// let next = trace_eval_next_row!(trace_eval, Column::IsPadding);
/// eval.add_constraint(next[0]);
/// ```
macro_rules! trace_eval_next_row {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval_next_row::<{ Column::size($col) }>($col)
    }};
}

pub(crate) use trace_eval_next_row;

/// Returns evaluations for a given column in preprocessed trace.
///
/// ```ignore
/// let trace_eval = TraceEval::new(&mut eval);
/// let curr_pc = trace_eval!(trace_eval, Column::Pc);
/// let (is_first, _) = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
/// for i in 0..WORD_SIZE {
///     eval.add_constraint(curr_pc[i] * is_first[0]);
/// }
/// ```
macro_rules! preprocessed_trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.preprocessed_column_eval::<{ PreprocessedColumn::size($col) }>($col)
    }};
}

pub(crate) use preprocessed_trace_eval;
