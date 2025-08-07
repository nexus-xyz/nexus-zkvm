use num_traits::One;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm_prover_trace::{eval::TraceEval, trace_eval};

use crate::lookups::RangeCheckLookupElements;

use super::{
    columns::{Column, PreprocessedColumn},
    ReadWriteMemory,
};

impl ReadWriteMemory {
    pub(super) fn constrain_ram_write<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        range_check: &RangeCheckLookupElements,
    ) {
        let [ram_write] = trace_eval!(trace_eval, Column::RamWrite);
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let ram_val_prev: Vec<E::F> = [
            Column::Ram1ValPrev,
            Column::Ram2ValPrev,
            Column::Ram3ValPrev,
            Column::Ram4ValPrev,
        ]
        .iter()
        .map(|col| trace_eval.column_eval::<1>(*col)[0].clone())
        .collect();

        let ram_val_cur: Vec<E::F> = [
            Column::Ram1ValCur,
            Column::Ram2ValCur,
            Column::Ram3ValCur,
            Column::Ram4ValCur,
        ]
        .iter()
        .map(|col| trace_eval.column_eval::<1>(*col)[0].clone())
        .collect();

        // cur value is range checked by execution components
        range_check
            .range256
            .constrain(eval, is_local_pad.clone(), &ram_val_prev);
        // ramj-val-prev = ramj-val-cur for j = 1, 2, 3, 4 for read operations
        for (ram_val_prev, ram_val_cur) in ram_val_prev.into_iter().zip(ram_val_cur) {
            eval.add_constraint((E::F::one() - ram_write.clone()) * (ram_val_cur - ram_val_prev));
        }
    }
}
