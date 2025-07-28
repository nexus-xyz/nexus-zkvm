use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm_prover_trace::{
    builder::TraceBuilder, component::ComponentTrace, eval::TraceEval, original_base_column,
    program::ProgramStep, trace_eval,
};

use crate::{
    lookups::{LogupTraceBuilder, RangeCheckLookupElements, RangeLookupBound},
    side_note::range_check::RangeCheckAccumulator,
};

use super::columns::{Column, PreprocessedColumn};

pub struct Decoding;

impl Decoding {
    pub(super) fn generate_decoding_trace_row(
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
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

        range_check_accum
            .range16
            .add_values_from_slice(&[op_a1_4, op_b0_3, op_c1_4]);
        range_check_accum
            .range8
            .add_values_from_slice(&[op_c5_7, op_c8_10]);
    }

    pub(super) fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        range_check: &RangeCheckLookupElements,
    ) {
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_b4] = trace_eval!(trace_eval, Column::OpB4);
        let [op_c0] = trace_eval!(trace_eval, Column::OpC0);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);

        // constrain op_a0, op_b4, op_c0, op_c11 ∈ {0, 1}
        for bit in [op_a0, op_b4, op_c0.clone(), op_c11.clone()] {
            eval.add_constraint(bit.clone() * (E::F::one() - bit));
        }

        let [op_a1_4] = trace_eval!(trace_eval, Column::OpA1_4);
        let [op_b0_3] = trace_eval!(trace_eval, Column::OpB0_3);
        let [op_c1_4] = trace_eval!(trace_eval, Column::OpC1_4);

        let [op_c5_7] = trace_eval!(trace_eval, Column::OpC5_7);
        let [op_c8_10] = trace_eval!(trace_eval, Column::OpC8_10);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        for col in [op_a1_4, op_b0_3, op_c1_4] {
            range_check
                .range16
                .constrain(eval, is_local_pad.clone(), col);
        }
        for col in [op_c5_7, op_c8_10] {
            range_check
                .range8
                .constrain(eval, is_local_pad.clone(), col);
        }
    }

    pub(super) fn generate_interaction_trace(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);

        let [op_a1_4] = original_base_column!(component_trace, Column::OpA1_4);
        let [op_b0_3] = original_base_column!(component_trace, Column::OpB0_3);
        let [op_c1_4] = original_base_column!(component_trace, Column::OpC1_4);

        let [op_c5_7] = original_base_column!(component_trace, Column::OpC5_7);
        let [op_c8_10] = original_base_column!(component_trace, Column::OpC8_10);

        for col in [op_a1_4, op_b0_3, op_c1_4] {
            range_check
                .range16
                .generate_logup_col(logup_trace_builder, is_local_pad.clone(), col);
        }
        for col in [op_c5_7, op_c8_10] {
            range_check
                .range8
                .generate_logup_col(logup_trace_builder, is_local_pad.clone(), col);
        }
    }
}
