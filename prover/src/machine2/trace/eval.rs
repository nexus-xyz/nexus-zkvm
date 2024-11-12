use std::array;

use stwo_prover::constraint_framework::EvalAtRow;

use super::Column;

// Trace evaluation at the current row, capturing current and previous values.
pub struct TraceEval<E: EvalAtRow>(Vec<[E::F; 2]>);

impl<E: EvalAtRow> TraceEval<E> {
    pub(crate) fn new(eval: &mut E) -> Self {
        let evals = std::iter::repeat_with(|| eval.next_interaction_mask(0, [-1, 0]))
            .take(Column::COLUMNS_NUM)
            .collect();
        Self(evals)
    }

    #[doc(hidden)]
    pub fn column_eval<const N: usize>(&self, col: Column) -> ([E::F; N], [E::F; N]) {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();

        (
            array::from_fn(|i| self.0[offset + i][0].clone()),
            array::from_fn(|i| self.0[offset + i][1].clone()),
        )
    }
}

/// Returns evaluations for a given column.
///
/// ```ignore
/// let trace_eval = TraceEval::new(&mut eval);
/// let (prev, curr) = trace_eval!(trace_eval, Column::IsAdd);
/// eval.add_constraint(curr[0] - prev[0]);
/// ```
macro_rules! trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval::<{ Column::size($col) }>($col)
    }};
}

pub(crate) use trace_eval;
