use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::TraceBuilder,
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    program::ProgramStep,
    trace_eval,
};

use super::{
    columns::{Column, PreprocessedColumn},
    LoadOp,
};
use crate::{
    components::utils::add_with_carries,
    lookups::{RangeCheckLookupElements, RangeLookupBound},
    side_note::range_check::RangeCheckAccumulator,
};

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum LwColumn {
    /// Loaded word
    #[size = 4]
    AVal,
    /// Helper column to enforce address alignment
    #[size = 1]
    HRamBaseAddrAux,
}

pub struct Lw;

impl LoadOp for Lw {
    const RAM2_ACCESSED: bool = true;
    const RAM3_4ACCESSED: bool = true;

    const OPCODE: BuiltinOpcode = BuiltinOpcode::LW;

    type LocalColumn = LwColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let value_a = program_step.get_result().expect("LW must have a result");

        trace.fill_columns(row_idx, value_a, LwColumn::AVal);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let (h_ram_base_addr, _) = add_with_carries(value_b, value_c);
        assert!(h_ram_base_addr[0].is_multiple_of(4));
        let h_ram_base_addr_aux = h_ram_base_addr[0] >> 2;
        trace.fill_columns(row_idx, h_ram_base_addr_aux, LwColumn::HRamBaseAddrAux);

        range_check_accum.range64.add_value(h_ram_base_addr_aux);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        range_check: &RangeCheckLookupElements,
    ) -> [[E::F; WORD_SIZE]; 2] {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let ram_values = trace_eval!(local_trace_eval, LwColumn::AVal);

        let h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);
        let [h_ram_base_addr_aux] = trace_eval!(local_trace_eval, LwColumn::HRamBaseAddrAux);

        // (1 − is-local-pad) · (4 · h-ram-base-addr-aux − h-ram-base-addr(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr_aux.clone() * BaseField::from(4) - h_ram_base_addr[0].clone()),
        );
        range_check
            .range64
            .constrain(eval, is_local_pad, h_ram_base_addr_aux);

        [ram_values.clone(), ram_values]
    }

    fn finalized_ram_values(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE] {
        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        std::array::from_fn(|i| (&local_trace[i]).into())
    }

    fn generate_interaction_trace(
        logup_trace_builder: &mut crate::lookups::LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);

        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        // skip bytes of a-val
        let h_ram_base_addr_aux = &local_trace[4];
        range_check.range64.generate_logup_col(
            logup_trace_builder,
            is_local_pad,
            h_ram_base_addr_aux.into(),
        );
    }
}
