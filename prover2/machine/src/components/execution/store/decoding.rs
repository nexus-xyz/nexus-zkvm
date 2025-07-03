use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{
    columns::{Column, PreprocessedColumn},
    Store, StoreOp,
};

impl<S: StoreOp> Store<S> {
    pub(super) fn generate_decoding_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let op_c_raw = program_step.step.instruction.op_c;
        let op_c0 = (op_c_raw & 0b1) as u8;
        let op_c1_4 = ((op_c_raw >> 1) & 0b1111) as u8;
        let op_c5_7 = ((op_c_raw >> 5) & 0b111) as u8;
        let op_c8_10 = ((op_c_raw >> 8) & 0b111) as u8;
        let op_c11 = ((op_c_raw >> 11) & 0b1) as u8;
        trace.fill_columns(row_idx, op_c0, Column::OpC0);
        trace.fill_columns(row_idx, op_c1_4, Column::OpC1_4);
        trace.fill_columns(row_idx, op_c5_7, Column::OpC5_7);
        trace.fill_columns(row_idx, op_c8_10, Column::OpC8_10);
        trace.fill_columns(row_idx, op_c11, Column::OpC11);

        let op_a_raw = program_step.step.instruction.op_a as u8;
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0b1111;

        trace.fill_columns(row_idx, op_a0, Column::OpA0);
        trace.fill_columns(row_idx, op_a1_4, Column::OpA1_4);

        let op_b_raw = program_step.step.instruction.op_b as u8;
        let op_b0_3 = op_b_raw & 0b1111;
        let op_b4 = (op_b_raw >> 4) & 0b1;
        trace.fill_columns(row_idx, op_b0_3, Column::OpB0_3);
        trace.fill_columns(row_idx, op_b4, Column::OpB4);
    }

    pub(super) fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) {
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_b4] = trace_eval!(trace_eval, Column::OpB4);
        let [op_c0] = trace_eval!(trace_eval, Column::OpC0);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);

        // constrain op_a0, op_b4, op_c0, op_c11 ∈ {0, 1}
        for bit in [op_a0, op_b4, op_c0.clone(), op_c11.clone()] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }

        let [op_c1_4] = trace_eval!(trace_eval, Column::OpC1_4);
        let [op_c5_7] = trace_eval!(trace_eval, Column::OpC5_7);
        let [op_c8_10] = trace_eval!(trace_eval, Column::OpC8_10);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let c_val = trace_eval!(trace_eval, Column::CVal);

        // (1 − is-local-pad) · (op-c0 + op-c1-4 · 2 + op-c5-7 · 2^5 − c-val(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (op_c0.clone()
                    + op_c1_4.clone() * BaseField::from(1 << 1)
                    + op_c5_7.clone() * BaseField::from(1 << 5)
                    - c_val[0].clone()),
        );

        // (1 − is-local-pad) · (op-c8-10 + op-c11 · (2^5 − 1) · 2^3 − c-val(2)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (op_c8_10.clone()
                    + op_c11.clone() * BaseField::from((1 << 5) - 1) * BaseField::from(1 << 3)
                    - c_val[1].clone()),
        );

        // (1 − is-local-pad) · (op-c11 · (2^8 − 1) − c-val(3)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (op_c11.clone() * BaseField::from((1 << 8) - 1) - c_val[2].clone()),
        );

        // (1 − is-local-pad) · (op-c11 · (2^8 − 1) − c-val(4)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (op_c11.clone() * BaseField::from((1 << 8) - 1) - c_val[3].clone()),
        );
    }
}
