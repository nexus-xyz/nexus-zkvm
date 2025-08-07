use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{eval::TraceEval, preprocessed_trace_eval, trace_eval};

use crate::lookups::RangeCheckLookupElements;

use super::{
    columns::{Column, PreprocessedColumn},
    RegisterMemory,
};

impl RegisterMemory {
    pub(super) fn constrain_timestamps<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        range_check: &RangeCheckLookupElements,
    ) {
        let is_local_pad = &trace_eval!(trace_eval, Column::IsLocalPad)[0];

        let [h1_aux_borrow] = trace_eval!(trace_eval, Column::H1AuxBorrow);
        let [h2_aux_borrow] = trace_eval!(trace_eval, Column::H2AuxBorrow);
        let [h3_aux_borrow] = trace_eval!(trace_eval, Column::H3AuxBorrow);

        // (h{j}-aux-borrow) · (1 − h{j}-aux-borrow) = 0 for j = 1, 2, 3
        eval.add_constraint(h1_aux_borrow.clone() * (E::F::one() - h1_aux_borrow.clone()));
        eval.add_constraint(h2_aux_borrow.clone() * (E::F::one() - h2_aux_borrow.clone()));
        eval.add_constraint(h3_aux_borrow.clone() * (E::F::one() - h3_aux_borrow.clone()));

        let reg1_ts_prev = trace_eval!(trace_eval, Column::Reg1TsPrev);
        let reg2_ts_prev = trace_eval!(trace_eval, Column::Reg2TsPrev);
        let reg3_ts_prev = trace_eval!(trace_eval, Column::Reg3TsPrev);

        let reg1_ts_cur = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Reg1TsCur);
        let reg2_ts_cur = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Reg2TsCur);
        let reg3_ts_cur = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Reg3TsCur);

        let reg1_ts_prev_aux = trace_eval!(trace_eval, Column::Reg1TsPrevAux);
        let reg2_ts_prev_aux = trace_eval!(trace_eval, Column::Reg2TsPrevAux);
        let reg3_ts_prev_aux = trace_eval!(trace_eval, Column::Reg3TsPrevAux);

        for timestamp_bytes in [
            &reg1_ts_prev,
            &reg2_ts_prev,
            &reg3_ts_prev,
            &reg1_ts_prev_aux,
            &reg2_ts_prev_aux,
            &reg3_ts_prev_aux,
        ] {
            range_check
                .range256
                .constrain(eval, is_local_pad.clone(), timestamp_bytes);
        }

        RegisterMemory::constrain_diff_minus_one(
            eval,
            h1_aux_borrow,
            reg1_ts_prev_aux,
            reg1_ts_cur,
            reg1_ts_prev,
            is_local_pad,
        );
        RegisterMemory::constrain_diff_minus_one(
            eval,
            h2_aux_borrow,
            reg2_ts_prev_aux,
            reg2_ts_cur,
            reg2_ts_prev,
            is_local_pad,
        );
        RegisterMemory::constrain_diff_minus_one(
            eval,
            h3_aux_borrow,
            reg3_ts_prev_aux,
            reg3_ts_cur,
            reg3_ts_prev,
            is_local_pad,
        );
    }

    fn constrain_diff_minus_one<E: EvalAtRow>(
        eval: &mut E,
        h_borrow_aux: <E as EvalAtRow>::F,
        reg_ts_prev_aux: [<E as EvalAtRow>::F; WORD_SIZE],
        reg_ts_cur: [<E as EvalAtRow>::F; WORD_SIZE],
        reg_ts_prev: [<E as EvalAtRow>::F; WORD_SIZE],
        is_local_pad: &E::F,
    ) {
        let modulus = E::F::from(256u32.into());

        // Enforcing reg{i}-ts-prev-aux = reg{i}-ts-cur − 1 − reg{i}-ts-prev for i = 1, 2, 3
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (reg_ts_prev_aux[0].clone()
                    + reg_ts_prev_aux[1].clone() * modulus.clone()
                    + reg_ts_prev[0].clone()
                    + reg_ts_prev[1].clone() * modulus.clone()
                    + E::F::one()
                    - (h_borrow_aux.clone() * E::F::from(BaseField::from(1 << 16))
                        + reg_ts_cur[0].clone()
                        + reg_ts_cur[1].clone() * modulus.clone())),
        );

        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (reg_ts_prev_aux[2].clone()
                    + reg_ts_prev_aux[3].clone() * modulus.clone()
                    + reg_ts_prev[2].clone()
                    + reg_ts_prev[3].clone() * modulus.clone()
                    + h_borrow_aux
                    - (reg_ts_cur[2].clone() + reg_ts_cur[3].clone() * modulus.clone())),
        );
    }
}
