use num_traits::{One, Zero};
use stwo::{core::fields::m31::BaseField, prover::backend::simd::m31::PackedBaseField};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{
    empty::EmptyPreprocessedColumn, AirColumn, PreprocessedAirColumn,
};
use nexus_vm_prover_trace::{
    builder::TraceBuilder,
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    program::ProgramStep,
    trace_eval,
    virtual_column::VirtualColumn,
};

use super::{
    columns::{Column, PreprocessedColumn},
    LoadOp,
};
use crate::{
    lookups::{RangeCheckLookupElements, RangeLookupBound},
    side_note::range_check::RangeCheckAccumulator,
};

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum LbColumn {
    /// Loaded lower byte
    #[size = 1]
    AVal,
    /// Lower 7 bits of the loaded byte
    #[size = 1]
    HRamValRem,
    /// Sign bit of the loaded byte
    #[size = 1]
    HRamValSign,
}

pub struct Lb;

impl LoadOp for Lb {
    const RAM2_ACCESSED: bool = false;
    const RAM3_4ACCESSED: bool = false;

    const OPCODE: BuiltinOpcode = BuiltinOpcode::LB;

    type LocalColumn = LbColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let value_a = program_step.get_result().expect("LB must have a result");
        let h_ram_val_rem = value_a[0] & 0x7F;
        let h_ram_val_sign = (value_a[0] >> 7) & 1;

        trace.fill_columns(row_idx, value_a[0], LbColumn::AVal);
        trace.fill_columns(row_idx, h_ram_val_rem, LbColumn::HRamValRem);
        trace.fill_columns(row_idx, h_ram_val_sign, LbColumn::HRamValSign);

        range_check_accum.range128.add_value(h_ram_val_rem);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        range_check: &RangeCheckLookupElements,
    ) -> [[E::F; WORD_SIZE]; 2] {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let [ram1_val] = trace_eval!(local_trace_eval, LbColumn::AVal);
        let [h_ram_val_rem] = trace_eval!(local_trace_eval, LbColumn::HRamValRem);
        let [h_ram_val_sign] = trace_eval!(local_trace_eval, LbColumn::HRamValSign);

        // (1 − is-local-pad) · (h-ram-val-rem + h-ram-val-sgn · 2^7 − ram1-val) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_val_rem.clone() + h_ram_val_sign.clone() * BaseField::from(1 << 7)
                    - ram1_val.clone()),
        );
        // (h-ram-val-sgn) · (1 − h-ram-val-sgn) = 0
        eval.add_constraint(h_ram_val_sign.clone() * (E::F::one() - h_ram_val_sign));

        range_check
            .range128
            .constrain(eval, is_local_pad, h_ram_val_rem);

        let sign_ext_byte = SIGN_EXT_BYTE.eval(local_trace_eval);
        [
            ram_values::<E>(ram1_val.clone()),
            reg3_value::<E>(ram1_val, sign_ext_byte),
        ]
    }

    fn finalized_ram_values(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE] {
        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        let ram1_val = FinalizedColumn::from(&local_trace[0]);

        std::array::from_fn(|i| {
            if i == 0 {
                ram1_val.clone()
            } else {
                BaseField::zero().into()
            }
        })
    }

    fn generate_interaction_trace(
        logup_trace_builder: &mut crate::lookups::LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);

        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        let h_ram_val_rem = &local_trace[1];
        range_check.range128.generate_logup_col(
            logup_trace_builder,
            is_local_pad,
            h_ram_val_rem.into(),
        );
    }
}

fn ram_values<E: EvalAtRow>(ram1_val: E::F) -> [E::F; WORD_SIZE] {
    std::array::from_fn(|i| {
        if i == 0 {
            ram1_val.clone()
        } else {
            E::F::zero()
        }
    })
}

fn reg3_value<E: EvalAtRow>(ram1_val: E::F, sign_ext_byte: E::F) -> [E::F; WORD_SIZE] {
    std::array::from_fn(|i| {
        if i == 0 {
            ram1_val.clone()
        } else {
            sign_ext_byte.clone()
        }
    })
}

/// A sign-extended byte: 0xFF if sign bit is set, 0x00 otherwise.
pub(super) struct SignExtByte<C>(pub C);
const SIGN_EXT_BYTE: SignExtByte<LbColumn> = SignExtByte(LbColumn::HRamValSign);

impl<C: AirColumn> VirtualColumn for SignExtByte<C> {
    type Column = C;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let [h_ram_val_sign] = trace_eval.column_eval(self.0);
        h_ram_val_sign * BaseField::from((1 << 8) - 1)
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        assert_eq!(
            component_trace.original_trace.len() - Column::COLUMNS_NUM,
            self.0.offset() + 1
        );
        let h_ram_val_sign = component_trace
            .original_trace
            .last()
            .expect("trace is not empty");
        h_ram_val_sign.data[vec_idx] * BaseField::from((1 << 8) - 1)
    }
}
