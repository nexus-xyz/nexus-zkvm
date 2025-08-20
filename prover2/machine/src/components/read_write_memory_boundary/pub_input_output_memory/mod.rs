//! Helper component needed to eliminate boundary logup terms for read-only and write-only memory segments.

use std::collections::BTreeMap;

use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{
            m31::{self, BaseField},
            qm31::SecureField,
        },
        ColumnVec,
    },
    prover::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::{
    emulator::{MemoryInitializationEntry, PublicOutputEntry},
    WORD_SIZE,
};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column, preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    components::utils::u32_to_16bit_parts_le,
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, LogupTraceBuilder,
        RamReadAddressLookupElements, RamReadWriteLookupElements, RamWriteAddressLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct PubMemoryBoundary;

impl PubMemoryBoundary {
    fn addr_iter<'a>(side_note: &'a SideNote) -> impl Iterator<Item = u32> + 'a {
        let program_ref = &side_note.program;

        let ro_memory = program_ref.ro_memory;
        let public_input = program_ref.public_input;
        let exit_code = program_ref.exit_code;
        let public_output = program_ref.public_output;

        let ro_iter = ro_memory.iter().chain(public_input);
        let wo_iter = exit_code.iter().chain(public_output);

        ro_iter
            .map(|entry| entry.address)
            .chain(wo_iter.map(|entry| entry.address))
    }

    fn generate_init_final_flag_column(side_note: &SideNote, log_size: u32) -> BaseColumn {
        let program_ref = &side_note.program;

        let ro_memory = program_ref.ro_memory;
        let public_input = program_ref.public_input;
        let exit_code = program_ref.exit_code;
        let public_output = program_ref.public_output;

        let len = ro_memory.len() + public_input.len() + exit_code.len() + public_output.len();
        assert!(1 << log_size >= len as u32);

        std::iter::repeat_n(BaseField::one(), len)
            .chain(std::iter::repeat(BaseField::zero()))
            .take(1 << log_size)
            .collect()
    }

    fn generate_ram_val_final_column(side_note: &SideNote, log_size: u32) -> BaseColumn {
        let program_ref = &side_note.program;

        let ro_memory = program_ref.ro_memory;
        let public_input = program_ref.public_input;
        let exit_code = program_ref.exit_code;
        let public_output = program_ref.public_output;

        let ro_iter = ro_memory.iter().chain(public_input);
        let wo_iter = exit_code.iter().chain(public_output);

        let val_iter = ro_iter
            .map(|entry| entry.value)
            .chain(wo_iter.map(|entry| entry.value));
        val_iter
            .map(|v| BaseField::from(v as u32))
            .chain(std::iter::repeat(BaseField::zero()))
            .take(1 << log_size)
            .collect()
    }
}

impl BuiltInComponent for PubMemoryBoundary {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        RamReadWriteLookupElements,
        RamReadAddressLookupElements,
        RamWriteAddressLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        program_ref: &ProgramTraceRef,
    ) -> FinalizedTrace {
        let mut trace = TraceBuilder::new(log_size);

        let ro_memory = program_ref.ro_memory;
        let public_input = program_ref.public_input;
        let exit_code = program_ref.exit_code;
        let public_output = program_ref.public_output;

        let init_memory_len = ro_memory.len() + public_input.len();
        let exit_code_len = exit_code.len();

        for (row_idx, MemoryInitializationEntry { address, value }) in
            ro_memory.iter().chain(public_input).enumerate()
        {
            trace.fill_columns(row_idx, *address, PreprocessedColumn::PubIoAddr);

            trace.fill_columns(row_idx, true, PreprocessedColumn::PubInFlag);
            trace.fill_columns(row_idx, *value, PreprocessedColumn::PubInVal);
        }
        let offset = init_memory_len;

        for (row_idx, PublicOutputEntry { address, value }) in exit_code.iter().enumerate() {
            let row_idx = row_idx + offset;
            trace.fill_columns(row_idx, *address, PreprocessedColumn::PubIoAddr);

            trace.fill_columns(row_idx, true, PreprocessedColumn::PubOutFlag);
            trace.fill_columns(row_idx, *value, PreprocessedColumn::PubOutVal);
        }
        let offset = offset + exit_code_len;

        for (row_idx, PublicOutputEntry { address, value }) in public_output.iter().enumerate() {
            let row_idx = row_idx + offset;
            trace.fill_columns(row_idx, *address, PreprocessedColumn::PubIoAddr);

            trace.fill_columns(row_idx, true, PreprocessedColumn::PubOutFlag);
            trace.fill_columns(row_idx, *value, PreprocessedColumn::PubOutVal);
        }
        trace.finalize()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let program_ref = &side_note.program;

        let ro_memory = program_ref.ro_memory;
        let public_input = program_ref.public_input;
        let exit_code = program_ref.exit_code;
        let public_output = program_ref.public_output;

        let len = ro_memory.len() + public_input.len() + exit_code.len() + public_output.len();

        let log_size = len.next_power_of_two().ilog2().max(LOG_N_LANES);
        let last_access = side_note.memory.read_write_memory.last_access();
        let read_mults: &BTreeMap<u32, u32> = &side_note.memory.read_access;
        let write_mults: &BTreeMap<u32, u32> = &side_note.memory.write_access;

        let mut trace = TraceBuilder::new(log_size);
        let addr_iter = Self::addr_iter(side_note);

        for (row_idx, address) in addr_iter.enumerate() {
            let (last_access, _last_value) = last_access.get(&address).copied().unwrap_or_default();
            assert!(last_access < m31::P, "Access counter overflow");

            let ts_final = u32_to_16bit_parts_le(last_access);
            trace.fill_columns(row_idx, ts_final, Column::RamTsFinal);

            let read_mult = read_mults.get(&address).copied().unwrap_or_default();
            let write_mult = write_mults.get(&address).copied().unwrap_or_default();
            trace.fill_columns_base_field(
                row_idx,
                &[BaseField::from(read_mult)],
                Column::MultiplicityRead,
            );
            trace.fill_columns_base_field(
                row_idx,
                &[BaseField::from(write_mult)],
                Column::MultiplicityWrite,
            );
        }

        trace.finalize()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let (rel_ram_read_write, rel_ram_read_addr, rel_ram_write_addr) =
            Self::LookupElements::get(lookup_elements);
        let log_size = component_trace.log_size();
        let mut logup_trace_builder = LogupTraceBuilder::new(log_size);

        let ram_init_final_flag: BaseColumn =
            Self::generate_init_final_flag_column(side_note, log_size);
        let ram_val_final = Self::generate_ram_val_final_column(side_note, log_size);

        let ram_ts_final = original_base_column!(component_trace, Column::RamTsFinal);
        let [ram_val_init] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::PubInVal);
        let ram_init_final_addr =
            preprocessed_base_column!(component_trace, PreprocessedColumn::PubIoAddr);

        let [read_mult] = original_base_column!(component_trace, Column::MultiplicityRead);
        let [write_mult] = original_base_column!(component_trace, Column::MultiplicityWrite);

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        logup_trace_builder.add_to_relation_with(
            &rel_ram_read_write,
            [(&ram_init_final_flag).into()],
            |[ram_init_final_flag]| (-ram_init_final_flag).into(),
            &[
                ram_init_final_addr.as_slice(),
                &[(&ram_val_final).into()],
                &ram_ts_final,
            ]
            .concat(),
        );
        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        logup_trace_builder.add_to_relation(
            &rel_ram_read_write,
            &ram_init_final_flag,
            &[
                ram_init_final_addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![BaseField::zero().into(); WORD_SIZE_HALVED].as_slice(),
            ]
            .concat(),
        );

        // consume(rel-ram-read-addr, read-mult, ram-init-final-addr)
        logup_trace_builder.add_to_relation_with(
            &rel_ram_read_addr,
            [read_mult],
            |[read_mult]| (-read_mult).into(),
            &ram_init_final_addr,
        );
        // consume(rel-ram-write-addr, write-mult, ram-init-final-addr)
        logup_trace_builder.add_to_relation_with(
            &rel_ram_write_addr,
            [write_mult],
            |[write_mult]| (-write_mult).into(),
            &ram_init_final_addr,
        );

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [pub_in_flag] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubInFlag);
        let [pub_out_flag] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubOutFlag);

        let pub_io_addr: [E::F; WORD_SIZE] =
            preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubIoAddr);

        let [pub_in_val] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubInVal);
        let [pub_out_val] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubOutVal);

        let [read_mult] = trace_eval!(trace_eval, Column::MultiplicityRead);
        let [write_mult] = trace_eval!(trace_eval, Column::MultiplicityWrite);

        // constrain read-only and write-only access
        eval.add_constraint(pub_in_flag.clone() * write_mult.clone());
        eval.add_constraint(pub_out_flag.clone() * read_mult.clone());
        // constrain multiplicities to be zeroed on padding rows
        eval.add_constraint(
            (E::F::one() - pub_in_flag.clone() - pub_out_flag.clone()) * read_mult.clone(),
        );
        eval.add_constraint(
            (E::F::one() - pub_in_flag.clone() - pub_out_flag.clone()) * write_mult.clone(),
        );

        let ram_val_init = pub_in_val.clone();

        let (rel_ram_read_write, rel_ram_read_addr, rel_ram_write_addr) = lookup_elements;
        let ram_ts_final = trace_eval!(trace_eval, Column::RamTsFinal);
        let ram_val_final = pub_in_val + pub_out_val;
        let ram_init_final_flag = pub_in_flag + pub_out_flag;

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            (-ram_init_final_flag.clone()).into(),
            &[
                pub_io_addr.as_slice(),
                std::slice::from_ref(&ram_val_final),
                &ram_ts_final,
            ]
            .concat(),
        ));
        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            ram_init_final_flag.into(),
            &[
                pub_io_addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![E::F::zero(); WORD_SIZE_HALVED].as_slice(),
            ]
            .concat(),
        ));

        // consume(rel-ram-read-addr, read-mult, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_addr,
            (-read_mult).into(),
            &pub_io_addr,
        ));
        // consume(rel-ram-write-addr, write-mult, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_write_addr,
            (-write_mult).into(),
            &pub_io_addr,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        components::ReadWriteMemory,
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    #[test]
    fn assert_rw_memory_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // First we create a usable address. heap start: 0x81008, heap end: 0x881008
            // Aiming to create 0x81008
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 1, 1, 19),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 8),
            // here x1 should be 0x80008
            // Setting x3 to be 128
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 128),
            // Storing a byte *x3 = 128 to memory address *x1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SB), 1, 3, 0),
        ])];

        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let _ = components_claimed_sum(&[&ReadWriteMemory], assert_ctx);
        let _claimed_sum = assert_component(PubMemoryBoundary, assert_ctx);
    }
}
