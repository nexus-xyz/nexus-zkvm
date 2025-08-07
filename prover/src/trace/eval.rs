use std::array;

use num_traits::Zero;
use stwo_constraint_framework::{preprocessed_columns::PreProcessedColumnId, EvalAtRow};

use crate::column::{
    Column, {PreprocessedColumn, ProgramColumn},
};

pub use stwo_constraint_framework::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

// Trace evaluation at the current row and the next row.
pub struct TraceEval<E: EvalAtRow> {
    evals: Vec<[E::F; 2]>,
    preprocessed_evals: Vec<E::F>,
    program_evals: Vec<E::F>, // only the current row
}

impl<E: EvalAtRow> TraceEval<E> {
    pub(crate) fn new(eval: &mut E) -> Self {
        let preprocessed_evals = PreprocessedColumn::STRING_IDS
            .iter()
            .map(|&id| eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_owned() }))
            .collect();
        let program_evals = ProgramColumn::STRING_IDS
            .iter()
            .map(|&id| eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_owned() }))
            .collect();
        let evals = Column::ALL_VARIANTS
            .iter()
            .flat_map(|col| std::iter::repeat_n(col, col.size()))
            .map(|col| {
                if col.reads_next_row_mask() {
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
            program_evals,
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
        assert!(
            col.reads_next_row_mask(),
            "{col:?} isn't allowed to read next row"
        );
        let offset = col.offset();

        array::from_fn(|i| self.evals[offset + i][1].clone())
    }

    #[doc(hidden)]
    pub fn preprocessed_column_eval<const N: usize>(&self, col: PreprocessedColumn) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();
        array::from_fn(|i| self.preprocessed_evals[offset + i].clone())
    }

    // #[doc(hidden)]
    // pub fn preprocessed_column_eval_next_row<const N: usize>(
    //     &self,
    //     col: PreprocessedColumn,
    // ) -> [E::F; N] {
    //     assert_eq!(col.size(), N, "column size mismatch");
    //     let offset = col.offset();

    //     array::from_fn(|i| self.preprocessed_evals[offset + i][1].clone())
    // }

    #[doc(hidden)]
    pub fn program_column_eval<const N: usize>(&self, col: ProgramColumn) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();

        array::from_fn(|i| self.program_evals[offset + i].clone())
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
/// let is_first = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
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

// /// Returns evaluations for a given column in preprocessed trace.
// ///
// /// ```ignore
// /// let trace_eval = TraceEval::new(&mut eval);
// /// let curr_pc = trace_eval!(trace_eval, Column::Pc);
// /// // When the next row has IsFirst, the current row is the last row.
// /// let is_last = preprocessed_trace_eval_next_row!(trace_eval, PreprocessedColumn::IsFirst);
// /// for i in 0..WORD_SIZE {
// ///     eval.add_constraint(curr_pc[i] * is_last[0]);
// /// }
// /// ```
// macro_rules! preprocessed_trace_eval_next_row {
//     ($traces:expr, $col:expr) => {{
//         $traces.preprocessed_column_eval_next_row::<{ PreprocessedColumn::size($col) }>($col)
//     }};
// }

// pub(crate) use preprocessed_trace_eval_next_row;

/// Returns evaluations for a given column in program trace.
///
/// ```ignore
/// let trace_eval = TraceEval::new(&mut eval);
/// let curr_pc = trace_eval!(trace_eval, Column::Pc);
/// let program_flag = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryFlag);
/// for i in 0..WORD_SIZE {
///     eval.add_constraint(curr_pc[i] * program_flag[0]);
/// }
/// ```
macro_rules! program_trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.program_column_eval::<{ ProgramColumn::size($col) }>($col)
    }};
}

pub(crate) use program_trace_eval;
