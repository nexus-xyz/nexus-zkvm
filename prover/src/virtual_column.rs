// A virtual column can be used like a column, but it is not stored in the trace. Instead, it is computed a very-low degree polynomial of other columns.

use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{backend::simd::m31::PackedBaseField, fields::m31::BaseField},
};

use crate::{
    column::Column::{self, ImmC, IsAdd, IsAnd, IsAuipc, IsLui, IsOr, IsSlt, IsSltu, IsSub, IsXor},
    trace::{eval::trace_eval, eval::TraceEval, FinalizedTraces, TracesBuilder},
};

pub(crate) trait VirtualColumn<const N: usize> {
    /// Reading BaseField elements from the TracesBuilder during main trace filling
    ///
    /// Currently there is no automatic checks against using this method before filling in the relevant columns.
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; N];
    /// Reading PackedBaseField elements from the FinalizedTraces during constraint generation
    fn read_from_finalized_traces(traces: &FinalizedTraces, vec_idx: usize)
        -> [PackedBaseField; N];
    /// Evaluating the virtual column during constraint evaluation
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; N];
}

pub(crate) struct IsTypeR;

impl IsTypeR {
    const TYPE_R_OPS: [Column; 7] = [
        IsAdd, IsSub, IsSlt, IsSltu, IsXor, IsOr, IsAnd,
        // TODO: SLL SRL SRA
    ];
}

impl VirtualColumn<1> for IsTypeR {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [imm_c] = traces.column(row_idx, ImmC);
        let ret = (BaseField::one() - imm_c)
            * Self::TYPE_R_OPS.iter().fold(BaseField::zero(), |acc, &op| {
                let [is_op] = traces.column(row_idx, op);
                acc + is_op
            });
        [ret]
    }
    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let imm_c = traces.get_base_column::<1>(ImmC)[0].data[vec_idx];
        let ret = (PackedBaseField::one() - imm_c)
            * Self::TYPE_R_OPS
                .iter()
                .fold(PackedBaseField::zero(), |acc, &op| {
                    let is_op = traces.get_base_column::<1>(op)[0].data[vec_idx];
                    acc + is_op
                });
        [ret]
    }
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [imm_c] = trace_eval!(trace_eval, ImmC);
        let ret = (E::F::one() - imm_c)
            * Self::TYPE_R_OPS.iter().fold(E::F::zero(), |acc, &op| {
                let [is_op] = trace_eval.column_eval(op);
                acc + is_op
            });
        [ret]
    }
}

pub(crate) struct IsTypeU;

impl IsTypeU {
    const TYPE_U_OPS: [Column; 2] = [IsLui, IsAuipc];
}

impl VirtualColumn<1> for IsTypeU {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let ret = Self::TYPE_U_OPS.iter().fold(BaseField::zero(), |acc, &op| {
            let [is_op] = traces.column(row_idx, op);
            acc + is_op
        });
        [ret]
    }
    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let ret = Self::TYPE_U_OPS
            .iter()
            .fold(PackedBaseField::zero(), |acc, &op| {
                let is_op = traces.get_base_column::<1>(op)[0].data[vec_idx];
                acc + is_op
            });
        [ret]
    }
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let ret = Self::TYPE_U_OPS.iter().fold(E::F::zero(), |acc, &op| {
            let [is_op] = trace_eval.column_eval(op);
            acc + is_op
        });
        [ret]
    }
}
