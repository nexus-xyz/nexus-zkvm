use std::collections::BTreeMap;
use stwo_prover::core::backend::simd::m31::LOG_N_LANES;

use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    program::ProgramStep,
};

use super::columns::Column;
use crate::{
    components::utils::{add_with_carries, u32_to_16bit_parts_le},
    side_note::{range_check::Range256Multiplicities, SideNote},
};

// Program memory side note can only be updated by the program memory component, once it's stored
// in the prover's side note it can only be used to fetch final program counters.

#[derive(Debug, Default)]
pub struct ProgramMemorySideNote {
    last_access: BTreeMap<u32, u32>,
}

impl ProgramMemorySideNote {
    pub fn last_access(&self) -> &BTreeMap<u32, u32> {
        &self.last_access
    }
}

pub fn generate_main_trace(side_note: &mut SideNote) -> FinalizedTrace {
    let num_steps = side_note.num_program_steps();
    let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

    let mut trace = TraceBuilder::new(log_size);
    let mut program_mem_side_note = ProgramMemorySideNote::default();
    let mut range_check_mults = Range256Multiplicities::default();

    for (row_idx, program_step) in side_note.iter_program_steps().enumerate() {
        generate_trace_row(
            &mut trace,
            row_idx,
            program_step,
            &mut program_mem_side_note,
            &mut range_check_mults,
        );
    }
    side_note.range_check.range256.append(range_check_mults);
    // store final program memory counters into side note
    side_note.memory.program_memory = program_mem_side_note;

    for row_idx in num_steps..1 << log_size {
        trace.fill_columns(row_idx, true, Column::IsLocalPad);
    }
    trace.finalize()
}

fn generate_trace_row(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
    reg_mem_side_note: &mut ProgramMemorySideNote,
    range_check_mults: &mut Range256Multiplicities,
) {
    let instr: u32 = program_step.step.raw_instruction;
    let pc: u32 = program_step.step.pc;
    let pc_access = reg_mem_side_note.last_access.entry(pc).or_insert(0);

    let prev_access_bytes = pc_access.to_le_bytes();
    *pc_access = pc_access.checked_add(1).expect("access counter overflow");

    let (next_access_bytes, carry) = add_with_carries(prev_access_bytes, 1u32.to_le_bytes());
    assert!(!carry[3]);

    let pc_parts = u32_to_16bit_parts_le(pc);
    let instr_parts = u32_to_16bit_parts_le(instr);
    trace.fill_columns(row_idx, pc_parts, Column::Pc);
    trace.fill_columns(row_idx, instr_parts, Column::InstrVal);

    trace.fill_columns(row_idx, prev_access_bytes, Column::ProgCtrPrev);
    trace.fill_columns(row_idx, next_access_bytes, Column::ProgCtrCur);
    trace.fill_columns(row_idx, carry[1], Column::ProgCtrCarry);

    range_check_mults.add_values(&prev_access_bytes);
    range_check_mults.add_values(&next_access_bytes);
}
