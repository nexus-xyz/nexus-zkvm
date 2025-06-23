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

use super::{columns::Column, Load, LoadOp};
use crate::{components::utils::add_with_carries, framework::BuiltInComponent};

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
    ) {
        let value_a = program_step.get_result().expect("LW must have a result");

        trace.fill_columns(row_idx, value_a, LwColumn::AVal);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let (h_ram_base_addr, _) = add_with_carries(value_b, value_c);
        assert!(h_ram_base_addr[0].is_multiple_of(4));
        trace.fill_columns(row_idx, h_ram_base_addr[0] / 4, LwColumn::HRamBaseAddrAux);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: TraceEval<
            <Load<Self> as BuiltInComponent>::PreprocessedColumn,
            <Load<Self> as BuiltInComponent>::MainColumn,
            E,
        >,
    ) -> [[E::F; WORD_SIZE]; 2] {
        // evaluate additional columns needed for the instruction
        // this line should be called exactly once per load component
        let local_trace_eval = TraceEval::<EmptyPreprocessedColumn, LwColumn, E>::new(eval);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let ram_values = trace_eval!(local_trace_eval, LwColumn::AVal);

        let h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);
        let [h_ram_base_addr_aux] = trace_eval!(local_trace_eval, LwColumn::HRamBaseAddrAux);

        // (1 − is-local-pad) · (4 · h-ram-base-addr-aux − h-ram-base-addr(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr_aux.clone() * BaseField::from(4) - h_ram_base_addr[0].clone()),
        );

        [ram_values.clone(), ram_values]
    }

    fn finalized_ram_values(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE] {
        let (_, local_trace) = component_trace.original_trace.split_at(Column::COLUMNS_NUM);
        std::array::from_fn(|i| (&local_trace[i]).into())
    }

    fn finalized_reg3_value(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE] {
        Self::finalized_ram_values(component_trace)
    }
}
