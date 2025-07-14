use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm_prover_trace::{
    builder::TraceBuilder, eval::TraceEval, program::ProgramStep, trace_eval,
};

use super::{Column, Jal, PreprocessedColumn};

impl Jal {
    pub(super) fn generate_decoding_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let op_c_raw = program_step.step.instruction.op_c;

        // Fill auxiliary columns for type J immediate value parsing
        let op_c1_3 = ((op_c_raw >> 1) & 0b111) as u8;
        let op_c4_7 = ((op_c_raw >> 4) & 0b1111) as u8;
        let op_c8_10 = ((op_c_raw >> 8) & 0b111) as u8;
        let op_c11 = ((op_c_raw >> 11) & 0b1) as u8;
        let op_c12_15 = ((op_c_raw >> 12) & 0b1111) as u8;
        let op_c16_19 = ((op_c_raw >> 16) & 0b1111) as u8;
        let op_c20 = ((op_c_raw >> 20) & 0b1) as u8;

        trace.fill_columns(row_idx, op_c1_3, Column::OpC1_3);
        trace.fill_columns(row_idx, op_c4_7, Column::OpC4_7);
        trace.fill_columns(row_idx, op_c8_10, Column::OpC8_10);
        trace.fill_columns(row_idx, op_c11, Column::OpC11);
        trace.fill_columns(row_idx, op_c12_15, Column::OpC12_15);
        trace.fill_columns(row_idx, op_c16_19, Column::OpC16_19);
        trace.fill_columns(row_idx, op_c20, Column::OpC20);

        let op_a_raw = program_step.step.instruction.op_a as u8;
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0b1111;

        trace.fill_columns(row_idx, op_a0, Column::OpA0);
        trace.fill_columns(row_idx, op_a1_4, Column::OpA1_4);
    }

    pub(super) fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) {
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);
        let [op_c20] = trace_eval!(trace_eval, Column::OpC20);

        // constrain op_a0, op_c11, op_c20 ∈ {0, 1}
        for bit in [op_a0, op_c11, op_c20] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }
    }
}
