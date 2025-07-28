use num_traits::{One, Zero};
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
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
    lb::SignExtByte,
    LoadOp,
};
use crate::{
    components::utils::add_with_carries,
    lookups::{RangeCheckLookupElements, RangeLookupBound},
    side_note::range_check::RangeCheckAccumulator,
};

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum LhColumn {
    /// Two loaded lower bytes
    #[size = 2]
    AVal,
    /// Lower 7 bits of the second loaded byte
    #[size = 1]
    HRamValRem,
    /// Helper column to enforce address alignment
    #[size = 1]
    HRamBaseAddrAux,
    /// Sign bit of the second loaded byte
    #[size = 1]
    HRamValSign,
}

pub struct Lh;

impl LoadOp for Lh {
    const RAM2_ACCESSED: bool = true;
    const RAM3_4ACCESSED: bool = false;

    const OPCODE: BuiltinOpcode = BuiltinOpcode::LH;

    type LocalColumn = LhColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let value_a = program_step.get_result().expect("LH must have a result");
        let h_ram_val_rem = value_a[1] & 0x7F;
        let h_ram_val_sign = (value_a[1] >> 7) & 1;

        trace.fill_columns(row_idx, [value_a[0], value_a[1]], LhColumn::AVal);
        trace.fill_columns(row_idx, h_ram_val_rem, LhColumn::HRamValRem);
        trace.fill_columns(row_idx, h_ram_val_sign, LhColumn::HRamValSign);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let (h_ram_base_addr, _) = add_with_carries(value_b, value_c);
        assert!(h_ram_base_addr[0].is_multiple_of(2));
        let h_ram_base_addr_aux = h_ram_base_addr[0] >> 1;
        trace.fill_columns(row_idx, h_ram_base_addr_aux, LhColumn::HRamBaseAddrAux);

        range_check_accum
            .range128
            .add_values_from_slice(&[h_ram_val_rem, h_ram_base_addr_aux]);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        range_check: &RangeCheckLookupElements,
    ) -> [[E::F; WORD_SIZE]; 2] {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let [ram1_val, ram2_val] = trace_eval!(local_trace_eval, LhColumn::AVal);
        let [h_ram_val_rem] = trace_eval!(local_trace_eval, LhColumn::HRamValRem);
        let [h_ram_val_sign] = trace_eval!(local_trace_eval, LhColumn::HRamValSign);

        let h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);
        let [h_ram_base_addr_aux] = trace_eval!(local_trace_eval, LhColumn::HRamBaseAddrAux);

        // (1 − is-local-pad) · (2 · h-ram-base-addr-aux − h-ram-base-addr(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr_aux.clone() * BaseField::from(2) - h_ram_base_addr[0].clone()),
        );
        // (1 − is-local-pad) · (h-ram-val-rem + h-ram-val-sgn · 2^7 − ram2-val) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_val_rem.clone() + h_ram_val_sign.clone() * BaseField::from(1 << 7)
                    - ram2_val.clone()),
        );
        // (h-ram-val-sgn) · (1 − h-ram-val-sgn) = 0
        eval.add_constraint(h_ram_val_sign.clone() * (E::F::one() - h_ram_val_sign));

        range_check
            .range128
            .constrain(eval, is_local_pad.clone(), h_ram_val_rem);
        range_check
            .range128
            .constrain(eval, is_local_pad.clone(), h_ram_base_addr_aux);

        let sign_ext_byte = SIGN_EXT_BYTE.eval(local_trace_eval);
        let ram_values = [
            ram1_val.clone(),
            ram2_val.clone(),
            E::F::zero(),
            E::F::zero(),
        ];
        let reg3_value = [ram1_val, ram2_val, sign_ext_byte.clone(), sign_ext_byte];
        [ram_values, reg3_value]
    }

    fn finalized_ram_values(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE] {
        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        let ram1_val = FinalizedColumn::from(&local_trace[0]);
        let ram2_val = FinalizedColumn::from(&local_trace[1]);

        let zero = FinalizedColumn::from(BaseField::zero());
        [ram1_val, ram2_val, zero.clone(), zero]
    }

    fn generate_interaction_trace(
        logup_trace_builder: &mut crate::lookups::LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);

        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        // skip bytes of a-val
        let h_ram_val_rem = &local_trace[2];
        let h_ram_base_addr_aux = &local_trace[3];
        range_check.range128.generate_logup_col(
            logup_trace_builder,
            is_local_pad.clone(),
            h_ram_val_rem.into(),
        );
        range_check.range128.generate_logup_col(
            logup_trace_builder,
            is_local_pad,
            h_ram_base_addr_aux.into(),
        );
    }
}

const SIGN_EXT_BYTE: SignExtByte<LhColumn> = SignExtByte(LhColumn::HRamValSign);
