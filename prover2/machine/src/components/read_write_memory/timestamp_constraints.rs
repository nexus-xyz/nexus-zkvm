use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{eval::TraceEval, trace_eval};

use crate::lookups::RangeCheckLookupElements;

use super::{
    columns::{Column, PreprocessedColumn},
    ReadWriteMemory,
};

impl ReadWriteMemory {
    pub(super) fn constrain_timestamps<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let ram_ts_prev_borrow: [E::F; 4] = [
            trace_eval!(trace_eval, Column::Ram1TsPrevBorrow)[0].clone(),
            trace_eval!(trace_eval, Column::Ram2TsPrevBorrow)[0].clone(),
            trace_eval!(trace_eval, Column::Ram3TsPrevBorrow)[0].clone(),
            trace_eval!(trace_eval, Column::Ram4TsPrevBorrow)[0].clone(),
        ];

        // ramj-ts-prev-borrow(1) ∈ {0, 1} for j = 1, 2, 3, 4
        for ram_ts_prev_borrow in &ram_ts_prev_borrow {
            eval.add_constraint(
                ram_ts_prev_borrow.clone() * (E::F::one() - ram_ts_prev_borrow.clone()),
            );
        }

        let ram_ts_prev = [
            Column::Ram1TsPrev,
            Column::Ram2TsPrev,
            Column::Ram3TsPrev,
            Column::Ram4TsPrev,
        ];
        let ram_ts_prev_aux = [
            Column::Ram1TsPrevAux,
            Column::Ram2TsPrevAux,
            Column::Ram3TsPrevAux,
            Column::Ram4TsPrevAux,
        ];
        let [clk_low, clk_high] = trace_eval!(trace_eval, Column::Clk);

        // ram{i}ts-prev-aux = clk − 1 − ram{i}-ts-prev for i = 1, 2, 3, 4
        for ((ram_ts_prev_borrow, ram_ts_prev), ram_ts_prev_aux) in ram_ts_prev_borrow
            .into_iter()
            .zip(ram_ts_prev)
            .zip(ram_ts_prev_aux)
        {
            let ram_ts_prev: [E::F; WORD_SIZE] = trace_eval.column_eval(ram_ts_prev);
            let ram_ts_prev_aux: [E::F; WORD_SIZE] = trace_eval.column_eval(ram_ts_prev_aux);
            for timestamp_bytes in [&ram_ts_prev, &ram_ts_prev_aux] {
                range_check
                    .range256
                    .constrain(eval, is_local_pad.clone(), timestamp_bytes);
            }

            eval.add_constraint(
                (E::F::one() - is_local_pad.clone())
                    * (clk_low.clone() + ram_ts_prev_borrow.clone() * BaseField::from(1 << 16)
                        - ram_ts_prev_aux[0].clone()
                        - ram_ts_prev_aux[1].clone() * BaseField::from(1 << 8)
                        - E::F::one()
                        - ram_ts_prev[0].clone()
                        - ram_ts_prev[1].clone() * BaseField::from(1 << 8)),
            );
            eval.add_constraint(
                (E::F::one() - is_local_pad.clone())
                    * (clk_high.clone()
                        - ram_ts_prev_aux[2].clone()
                        - ram_ts_prev_aux[3].clone() * BaseField::from(1 << 8)
                        - ram_ts_prev_borrow
                        - ram_ts_prev[2].clone()
                        - ram_ts_prev[3].clone() * BaseField::from(1 << 8)),
            );
        }
    }
}
