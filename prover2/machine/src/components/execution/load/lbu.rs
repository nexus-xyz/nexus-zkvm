use num_traits::Zero;
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
use crate::{lookups::RangeCheckLookupElements, side_note::range_check::RangeCheckAccumulator};

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum LbuColumn {
    /// Loaded lower byte
    #[size = 1]
    AVal,
}

pub struct Lbu;

impl LoadOp for Lbu {
    const RAM2_ACCESSED: bool = false;
    const RAM3_4ACCESSED: bool = false;

    const OPCODE: BuiltinOpcode = BuiltinOpcode::LBU;

    type LocalColumn = LbuColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
        _range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let value_a = program_step.get_result().expect("LBU must have a result");
        trace.fill_columns(row_idx, value_a[0], LbuColumn::AVal);
    }

    fn add_constraints<E: EvalAtRow>(
        _eval: &mut E,
        _trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        _range_check: &RangeCheckLookupElements,
    ) -> [[E::F; WORD_SIZE]; 2] {
        let [ram1_val] = trace_eval!(local_trace_eval, LbuColumn::AVal);

        let ram_values = ram_values::<E>(ram1_val);
        [ram_values.clone(), ram_values]
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
        _: &mut crate::lookups::LogupTraceBuilder,
        _: &ComponentTrace,
        _: &RangeCheckLookupElements,
    ) {
        // no range checks
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
