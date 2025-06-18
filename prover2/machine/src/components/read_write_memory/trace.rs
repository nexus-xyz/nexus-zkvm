use std::collections::BTreeMap;
use stwo_prover::core::backend::simd::m31::LOG_N_LANES;

use nexus_vm::{emulator::MemoryInitializationEntry, riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    program::ProgramStep,
};

use super::columns::Column;
use crate::{
    components::utils::{add_with_carries, decr_subtract_with_borrow, u32_to_16bit_parts_le},
    side_note::SideNote,
};

// Read-write memory side note can only be updated by the read-write memory component, once it's stored
// in the prover's side note it can only be used to fetch final memory state.

#[derive(Default)]
pub struct ReadWriteMemorySideNote {
    /// u32 is the access counter, u8 is the value of the byte
    last_access: BTreeMap<u32, (u32, u8)>,
}

impl ReadWriteMemorySideNote {
    pub fn new(init_memory: &[MemoryInitializationEntry]) -> Self {
        let mut last_access = BTreeMap::default();
        for MemoryInitializationEntry { address, value } in init_memory {
            let old = last_access.insert(*address, (0, *value));
            assert!(old.is_none(), "Duplicate memory initialization entry");
        }

        Self { last_access }
    }

    pub fn last_access(&self) -> &BTreeMap<u32, (u32, u8)> {
        &self.last_access
    }
}

fn iter_program_steps<'a>(side_note: &SideNote<'a>) -> impl Iterator<Item = ProgramStep<'a>> {
    side_note.iter_program_steps().filter(move |step| {
        matches!(
            step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SB)
                | Some(BuiltinOpcode::SH)
                | Some(BuiltinOpcode::SW)
                | Some(BuiltinOpcode::LB)
                | Some(BuiltinOpcode::LH)
                | Some(BuiltinOpcode::LBU)
                | Some(BuiltinOpcode::LHU)
                | Some(BuiltinOpcode::LW)
        )
    })
}

pub fn generate_main_trace(side_note: &mut SideNote) -> FinalizedTrace {
    let mut rw_memory_side_note = ReadWriteMemorySideNote::new(side_note.init_memory());

    let num_memory_steps = iter_program_steps(side_note).count();
    let log_size = num_memory_steps
        .next_power_of_two()
        .ilog2()
        .max(LOG_N_LANES);

    let mut trace = TraceBuilder::new(log_size);
    for (row_idx, program_step) in iter_program_steps(side_note).enumerate() {
        generate_trace_row(&mut trace, row_idx, program_step, &mut rw_memory_side_note);
    }

    // store final ram state into side note
    *side_note.read_write_memory_mut() = rw_memory_side_note;

    // fill padding
    for row_idx in num_memory_steps..1 << log_size {
        trace.fill_columns(row_idx, true, Column::IsLocalPad);
    }
    trace.finalize()
}

fn generate_trace_row(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
    rw_memory_side_note: &mut ReadWriteMemorySideNote,
) {
    let is_load = matches!(
        program_step.step.instruction.opcode.builtin(),
        Some(BuiltinOpcode::LB)
            | Some(BuiltinOpcode::LH)
            | Some(BuiltinOpcode::LW)
            | Some(BuiltinOpcode::LBU)
            | Some(BuiltinOpcode::LHU)
    );

    let value_a = program_step.get_value_a();
    let value_b = program_step.get_value_b();
    let (offset, effective_bits) = program_step.get_value_c();
    assert_eq!(effective_bits, 12);

    let clk = program_step.step.timestamp;
    let clk_parts = u32_to_16bit_parts_le(clk);
    let (ram_base_address, _) = if is_load {
        add_with_carries(value_b, offset)
    } else {
        add_with_carries(value_a, offset)
    };
    trace.fill_columns(row_idx, ram_base_address, Column::RamBaseAddr);
    trace.fill_columns(row_idx, clk_parts, Column::Clk);

    for memory_record in &program_step.step.memory_records {
        assert_eq!(memory_record.get_timestamp(), clk, "timestamp mismatch");
        let byte_address = memory_record.get_address();
        assert_eq!(
            byte_address,
            u32::from_le_bytes(ram_base_address),
            "address mismatch"
        );

        let access_size = memory_record.get_size() as usize;

        if !is_load {
            assert!(
                (memory_record.get_prev_value().unwrap() as u64) < { 1u64 } << (access_size * 8),
                "memory operation previous value overflow"
            );
            trace.fill_columns(row_idx, true, Column::RamWrite);
        }
        assert!(
            (memory_record.get_value() as u64) < { 1u64 } << (access_size * 8),
            "memory operation next value overflow"
        );

        let cur_value = memory_record.get_value().to_le_bytes();
        let prev_value = if is_load {
            cur_value
        } else {
            memory_record
                .get_prev_value()
                .expect("store operation must have a previous value")
                .to_le_bytes()
        };

        let ram_cols = [
            (
                Column::Ram1Accessed,
                Column::Ram1ValCur,
                Column::Ram1ValPrev,
                Column::Ram1TsPrev,
                Column::Ram1TsPrevAux,
                Column::Ram1TsPrevBorrow,
            ),
            (
                Column::Ram2Accessed,
                Column::Ram2ValCur,
                Column::Ram2ValPrev,
                Column::Ram2TsPrev,
                Column::Ram2TsPrevAux,
                Column::Ram2TsPrevBorrow,
            ),
            (
                Column::Ram3_4Accessed,
                Column::Ram3ValCur,
                Column::Ram3ValPrev,
                Column::Ram3TsPrev,
                Column::Ram3TsPrevAux,
                Column::Ram3TsPrevBorrow,
            ),
            (
                Column::Ram3_4Accessed,
                Column::Ram4ValCur,
                Column::Ram4ValPrev,
                Column::Ram4TsPrev,
                Column::Ram4TsPrevAux,
                Column::Ram4TsPrevBorrow,
            ),
        ];

        for (i, (ram_accessed, val_cur, val_prev, ts_prev, ram_ts_prev_aux, helper)) in
            ram_cols[..access_size].iter().enumerate()
        {
            let prev_access = rw_memory_side_note.last_access.insert(
                byte_address
                    .checked_add(i as u32)
                    .expect("memory access address overflow"),
                (clk, cur_value[i]),
            );
            let (prev_timestamp, prev_val) = prev_access.unwrap_or((0, 0));
            if is_load {
                assert_eq!(
                    prev_val,
                    prev_value[i],
                    "memory access value mismatch at address 0x{:x}, prev_timestamp = {}",
                    byte_address.checked_add(i as u32).unwrap(),
                    prev_timestamp,
                );
            }

            trace.fill_columns(row_idx, true, *ram_accessed);
            trace.fill_columns(row_idx, cur_value[i], *val_cur);
            trace.fill_columns(row_idx, prev_val, *val_prev);
            trace.fill_columns(row_idx, prev_timestamp, *ts_prev);

            // timestamps
            let (ram_ts_prev_aux_word, ram_ts_prev_borrow) =
                decr_subtract_with_borrow(clk.to_le_bytes(), prev_timestamp.to_le_bytes());
            assert!(!ram_ts_prev_borrow[3]);
            trace.fill_columns(row_idx, ram_ts_prev_aux_word, *ram_ts_prev_aux);
            trace.fill_columns(row_idx, ram_ts_prev_borrow[1], *helper);
        }

        for (.., ram_ts_prev_aux, helper) in &ram_cols[access_size..] {
            // timestamp constraints must be satisfied on non-accessed ram, compute clk - 1 - 0
            let (ram_ts_prev_aux_word, ram_ts_prev_borrow) =
                decr_subtract_with_borrow(clk.to_le_bytes(), [0u8; WORD_SIZE]);
            assert!(!ram_ts_prev_borrow[3]);
            trace.fill_columns(row_idx, ram_ts_prev_aux_word, *ram_ts_prev_aux);
            trace.fill_columns(row_idx, ram_ts_prev_borrow[1], *helper);
        }
    }
}
