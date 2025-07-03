use stwo_prover::core::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES},
    fields::m31::BaseField,
};

use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    program::ProgramStep,
};

use super::columns::Column;
use crate::{components::utils::u32_to_16bit_parts_le, side_note::SideNote};

/// Returns low and high parts of the cpu clock.
pub fn preprocessed_clk_trace(log_size: u32) -> Vec<BaseColumn> {
    let (clk_low, clk_high): (Vec<BaseField>, Vec<BaseField>) = (1..=(1 << log_size))
        .map(|clk| {
            let [clk_low, clk_high] = u32_to_16bit_parts_le(clk);
            (
                BaseField::from(clk_low as u32),
                BaseField::from(clk_high as u32),
            )
        })
        .unzip();
    let clk_low = BaseColumn::from_iter(clk_low);
    let clk_high = BaseColumn::from_iter(clk_high);
    vec![clk_low, clk_high]
}

pub fn generate_main_trace(side_note: &mut SideNote) -> FinalizedTrace {
    let num_steps = side_note.num_program_steps();
    let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

    let mut trace = TraceBuilder::new(log_size);
    for (row_idx, program_step) in side_note.iter_program_steps().enumerate() {
        generate_trace_row(&mut trace, row_idx, program_step, side_note);
    }

    for row_idx in num_steps..1 << log_size {
        trace.fill_columns(row_idx, true, Column::IsPad);
    }
    trace.finalize()
}

fn generate_trace_row(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
    _side_note: &mut SideNote,
) {
    let step = &program_step.step;
    let pc = step.pc;

    let pc_bytes = pc.to_le_bytes();
    let pc_aux = pc_bytes[0] / 4;

    trace.fill_columns_bytes(row_idx, &pc_bytes, Column::Pc);
    trace.fill_columns(row_idx, pc_aux, Column::PcAux);
}
