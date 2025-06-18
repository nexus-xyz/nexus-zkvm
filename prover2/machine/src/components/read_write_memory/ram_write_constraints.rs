use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm_prover_trace::{eval::TraceEval, trace_eval};

use super::{
    columns::{Column, PreprocessedColumn},
    ReadWriteMemory,
};

impl ReadWriteMemory {
    pub(super) fn constrain_ram_write<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) {
        let [ram_write] = trace_eval!(trace_eval, Column::RamWrite);

        let ram_val_prev = [
            Column::Ram1ValPrev,
            Column::Ram2ValPrev,
            Column::Ram3ValPrev,
            Column::Ram4ValPrev,
        ];
        let ram_val_cur = [
            Column::Ram1ValCur,
            Column::Ram2ValCur,
            Column::Ram3ValCur,
            Column::Ram4ValCur,
        ];

        // ramj-val-prev = ramj-val-cur for j = 1, 2, 3, 4 for read operations
        for (ram_val_prev, ram_val_cur) in ram_val_prev.into_iter().zip(ram_val_cur) {
            let [ram_val_prev] = trace_eval.column_eval(ram_val_prev);
            let [ram_val_cur] = trace_eval.column_eval(ram_val_cur);

            eval.add_constraint((E::F::one() - ram_write.clone()) * (ram_val_cur - ram_val_prev));
        }
    }
}
