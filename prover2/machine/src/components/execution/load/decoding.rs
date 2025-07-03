use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{
    columns::{Column, PreprocessedColumn},
    Load, LoadOp,
};

impl<L: LoadOp> Load<L> {
    pub(super) fn generate_decoding_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let op_a_raw = program_step.step.instruction.op_a as u8;
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0xF;
        trace.fill_columns(row_idx, op_a0, Column::OpA0);
        trace.fill_columns(row_idx, op_a1_4, Column::OpA1_4);

        let op_b_raw = program_step.step.instruction.op_b as u8;
        let op_b0 = op_b_raw & 0x1;
        let op_b1_4 = (op_b_raw >> 1) & 0xF;
        trace.fill_columns(row_idx, op_b0, Column::OpB0);
        trace.fill_columns(row_idx, op_b1_4, Column::OpB1_4);

        let op_c_raw = program_step.step.instruction.op_c;
        let op_c0_3 = op_c_raw & 0xF;
        let op_c4_7 = (op_c_raw >> 4) & 0xF;
        let op_c8_10 = (op_c_raw >> 8) & 0x7;
        let op_c11 = (op_c_raw >> 11) & 0x1;
        trace.fill_columns(row_idx, op_c0_3 as u8, Column::OpC0_3);
        trace.fill_columns(row_idx, op_c4_7 as u8, Column::OpC4_7);
        trace.fill_columns(row_idx, op_c8_10 as u8, Column::OpC8_10);
        trace.fill_columns(row_idx, op_c11 as u8, Column::OpC11);
    }

    pub(super) fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) {
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_b0] = trace_eval!(trace_eval, Column::OpB0);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);

        // constrain op_a0, op_b0, op_c11 ∈ {0, 1}
        for bit in [op_a0, op_b0, op_c11.clone()] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }

        let [op_c0_3] = trace_eval!(trace_eval, Column::OpC0_3);
        let [op_c4_7] = trace_eval!(trace_eval, Column::OpC4_7);
        let [op_c8_10] = trace_eval!(trace_eval, Column::OpC8_10);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let c_val = trace_eval!(trace_eval, Column::CVal);

        // constrain c-val to equal 12-bit immediate
        //
        // (1 − is-local-pad) · (op-c0-3 + op-c4-7 · 2^4 − c-val(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (op_c0_3.clone() + op_c4_7.clone() * BaseField::from(1 << 4) - c_val[0].clone()),
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
