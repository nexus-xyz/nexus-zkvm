use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{eval::TraceEval, trace_eval};

use super::{
    columns::{Column, PreprocessedColumn},
    RegisterMemory,
};

impl RegisterMemory {
    pub(super) fn constrain_reg3<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) {
        let [reg3_write] = trace_eval!(trace_eval, Column::Reg3Write);
        let [reg3_addr] = trace_eval!(trace_eval, Column::Reg3Addr);

        let reg3_val = trace_eval!(trace_eval, Column::Reg3Val);
        let reg3_val_cur = trace_eval!(trace_eval, Column::Reg3ValCur);
        let reg3_val_prev = trace_eval!(trace_eval, Column::Reg3ValPrev);

        // (1 − reg3-write) · (reg3-val-cur − reg3-val-prev) = 0
        eval.add_constraint(
            (E::F::one() - reg3_write.clone())
                * (reg3_val_cur[0].clone() + reg3_val_cur[1].clone() * BaseField::from(1 << 8)
                    - (reg3_val_prev[0].clone()
                        + reg3_val_prev[1].clone() * BaseField::from(1 << 8))),
        );
        eval.add_constraint(
            (E::F::one() - reg3_write.clone())
                * (reg3_val_cur[2].clone() + reg3_val_cur[3].clone() * BaseField::from(1 << 8)
                    - (reg3_val_prev[2].clone()
                        + reg3_val_prev[3].clone() * BaseField::from(1 << 8))),
        );

        let [reg3_val_effective_flag] = trace_eval!(trace_eval, Column::Reg3ValEffectiveFlag);
        let [reg3_val_effective_flag_aux] =
            trace_eval!(trace_eval, Column::Reg3ValEffectiveFlagAux);
        let [reg3_val_effective_flag_aux_inv] =
            trace_eval!(trace_eval, Column::Reg3ValEffectiveFlagAuxInv);

        // reg3-addr · reg3-val-effective-flag-aux = reg3-val-effective-flag
        eval.add_constraint(
            reg3_addr.clone() * reg3_val_effective_flag_aux.clone()
                - reg3_val_effective_flag.clone(),
        );
        // reg3-val-effective-flag-aux · reg3-val-effective-flag-aux-inv = 1
        eval.add_constraint(
            reg3_val_effective_flag_aux.clone() * reg3_val_effective_flag_aux_inv - E::F::one(),
        );
        // (reg3-val-effective-flag) · (1 − reg3-val-effective-flag) = 0
        eval.add_constraint(
            reg3_val_effective_flag.clone() * (E::F::one() - reg3_val_effective_flag.clone()),
        );
        // reg3-val(i) · reg3-val-effective-flag = reg3-val-cur(i) for i = 1, 2, 3, 4
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                reg3_val[i].clone() * reg3_val_effective_flag.clone() - reg3_val_cur[i].clone(),
            );
        }
    }
}
