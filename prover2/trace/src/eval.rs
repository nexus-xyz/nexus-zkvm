use std::{array, marker::PhantomData};

use num_traits::Zero;
use stwo_constraint_framework::{preprocessed_columns::PreProcessedColumnId, EvalAtRow};

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

pub use stwo_constraint_framework::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

/// Trace evaluation at the current and next rows.
///
/// Initializing this struct in [`FrameworkEval::evaluate`] allows indexing trace masks with [`AirColumn`]
/// and [`PreprocessedAirColumn`] enums.
pub struct TraceEval<P, C, E: EvalAtRow> {
    evals: Vec<[E::F; 2]>,
    preprocessed_evals: Vec<E::F>,
    _phantom_data: PhantomData<(P, C)>,
}

impl<P: PreprocessedAirColumn, C: AirColumn, E: EvalAtRow> TraceEval<P, C, E> {
    pub fn new(eval: &mut E) -> Self {
        let preprocessed_evals = <P as PreprocessedAirColumn>::PREPROCESSED_IDS
            .iter()
            .map(|&id| eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_owned() }))
            .collect();
        let evals = <C as AirColumn>::ALL_VARIANTS
            .iter()
            .flat_map(|col| std::iter::repeat_n(col, col.size()))
            .map(|col| {
                if col.mask_next_row() {
                    eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1])
                } else {
                    [
                        eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone(),
                        <E::F as Zero>::zero(), // pad with zero, this value shouldn't be accessed
                    ]
                }
            })
            .collect();
        Self {
            evals,
            preprocessed_evals,
            _phantom_data: PhantomData,
        }
    }

    #[doc(hidden)]
    pub fn column_eval<const N: usize>(&self, col: C) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();

        array::from_fn(|i| self.evals[offset + i][0].clone())
    }

    #[doc(hidden)]
    pub fn column_eval_next_row<const N: usize>(&self, col: C) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        assert!(
            col.mask_next_row(),
            "{col:?} isn't allowed to read next row"
        );
        let offset = col.offset();

        array::from_fn(|i| self.evals[offset + i][1].clone())
    }

    #[doc(hidden)]
    pub fn preprocessed_column_eval<const N: usize>(&self, col: P) -> [E::F; N] {
        assert_eq!(col.size(), N, "preprocessed column size mismatch");
        let offset = col.offset();
        array::from_fn(|i| self.preprocessed_evals[offset + i].clone())
    }
}

pub fn shared_preprocessed_column<const N: usize, E: EvalAtRow, P: PreprocessedAirColumn>(
    eval: &mut E,
    col: P,
) -> [E::F; N] {
    assert_eq!(col.size(), N, "preprocessed column size mismatch");
    let offset = col.offset();
    array::from_fn(|i| {
        let id = <P as PreprocessedAirColumn>::PREPROCESSED_IDS[offset + i].to_owned();
        eval.get_preprocessed_column(PreProcessedColumnId { id })
    })
}

/// Returns evaluations for a given column.
///
/// ```ignore
/// let trace_eval = TraceEval::new(&mut eval);
/// let curr = trace_eval!(trace_eval, Column::IsAdd);
/// eval.add_constraint(curr[0]);
/// ```
#[macro_export]
macro_rules! trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval::<{ $col.const_size() }>($col)
    }};
}

/// Returns evaluations for a given column on the next row.
///
/// ```ignore
/// let trace_eval_next_row = TraceEval::new(&mut eval);
/// let next = trace_eval_next_row!(trace_eval, Column::IsPadding);
/// eval.add_constraint(next[0]);
/// ```
#[macro_export]
macro_rules! trace_eval_next_row {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval_next_row::<{ $col.const_size() }>($col)
    }};
}

/// Returns evaluations for a given column in preprocessed trace.
///
/// ```ignore
/// let trace_eval = TraceEval::new(&mut eval);
/// let curr_pc = trace_eval!(trace_eval, Column::Pc);
/// let is_first = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
/// for i in 0..WORD_SIZE {
///     eval.add_constraint(curr_pc[i] * is_first[0]);
/// }
/// ```
#[macro_export]
macro_rules! preprocessed_trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.preprocessed_column_eval::<{ $col.const_size() }>($col)
    }};
}

#[cfg(test)]
mod tests {
    use nexus_vm_prover_air_column::empty::EmptyPreprocessedColumn;
    use stwo_constraint_framework::{FrameworkEval, InfoEvaluator};

    use super::*;

    #[derive(Debug, Copy, Clone, AirColumn)]
    enum TestColumn {
        #[size = 1]
        A,
        #[size = 2]
        B,
        #[size = 3]
        #[mask_next_row]
        C,
    }

    struct TestEval;

    impl FrameworkEval for TestEval {
        fn log_size(&self) -> u32 {
            1
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let trace_eval = TraceEval::<EmptyPreprocessedColumn, TestColumn, E>::new(&mut eval);

            #[allow(unused)]
            {
                let [a0] = trace_eval!(trace_eval, TestColumn::A);
                let [b0, b1] = trace_eval!(trace_eval, TestColumn::B);
                let [c00, c01, c02] = trace_eval!(trace_eval, TestColumn::C);
                let [c10, c11, c12] = trace_eval_next_row!(trace_eval, TestColumn::C);
            }
            eval
        }
    }

    #[test]
    fn eval_column_layout() {
        let info = TestEval::evaluate(&TestEval, InfoEvaluator::empty());

        assert_eq!(
            info.mask_offsets[1].len(),
            <TestColumn as AirColumn>::COLUMNS_NUM
        );
        assert!(info.mask_offsets[1][..TestColumn::C.const_offset()]
            .iter()
            .all(|mask| mask == &[0]));
        assert!(info.mask_offsets[1][TestColumn::C.const_offset()..]
            .iter()
            .all(|mask| mask == &[0, 1]));
    }
}
