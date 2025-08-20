//! Helper component needed to eliminate boundary logup terms for static read-write memory segment.

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
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::emulator::MemoryInitializationEntry;
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

pub struct StaticMemoryBoundary;

impl BuiltInComponent for StaticMemoryBoundary {
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
        let static_memory = program_ref.static_memory;
        assert!(1 << log_size >= static_memory.len());

        let mut trace = TraceBuilder::new(log_size);
        for (row_idx, MemoryInitializationEntry { address, value }) in
            static_memory.iter().enumerate()
        {
            trace.fill_columns(row_idx, true, PreprocessedColumn::IsStaticAddr);
            trace.fill_columns(row_idx, *address, PreprocessedColumn::Address);
            trace.fill_columns(row_idx, *value, PreprocessedColumn::InitVal);
        }

        trace.finalize()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let static_memory = side_note.program.static_memory;
        let last_access = side_note.memory.read_write_memory.last_access();
        let read_mults: &BTreeMap<u32, u32> = &side_note.memory.read_access;
        let write_mults: &BTreeMap<u32, u32> = &side_note.memory.write_access;

        let log_size = static_memory
            .len()
            .next_power_of_two()
            .ilog2()
            .max(LOG_N_LANES);

        let mut trace = TraceBuilder::new(log_size);
        for (row_idx, MemoryInitializationEntry { address, .. }) in static_memory.iter().enumerate()
        {
            let (last_access, last_value) = last_access.get(address).copied().unwrap_or_default();
            assert!(last_access < m31::P, "Access counter overflow");

            let ts_final = u32_to_16bit_parts_le(last_access);
            trace.fill_columns(row_idx, ts_final, Column::RamTsFinal);
            trace.fill_columns(row_idx, last_value, Column::RamValFinal);

            let read_mult = read_mults.get(address).copied().unwrap_or_default();
            let write_mult = write_mults.get(address).copied().unwrap_or_default();
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
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let (rel_ram_read_write, rel_ram_read_addr, rel_ram_write_addr) =
            Self::LookupElements::get(lookup_elements);
        let log_size = component_trace.log_size();
        let mut logup_trace_builder = LogupTraceBuilder::new(log_size);

        let [ram_init_final_flag] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::IsStaticAddr);
        let addr = preprocessed_base_column!(component_trace, PreprocessedColumn::Address);
        let [ram_val_init] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::InitVal);

        let [ram_val_final] = original_base_column!(component_trace, Column::RamValFinal);
        let ram_ts_final = original_base_column!(component_trace, Column::RamTsFinal);

        let [read_mult] = original_base_column!(component_trace, Column::MultiplicityRead);
        let [write_mult] = original_base_column!(component_trace, Column::MultiplicityWrite);

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        logup_trace_builder.add_to_relation_with(
            &rel_ram_read_write,
            [ram_init_final_flag.clone()],
            |[ram_init_final_flag]| (-ram_init_final_flag).into(),
            &[
                addr.as_slice(),
                std::slice::from_ref(&ram_val_final),
                &ram_ts_final,
            ]
            .concat(),
        );
        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        logup_trace_builder.add_to_relation(
            &rel_ram_read_write,
            ram_init_final_flag,
            &[
                addr.as_slice(),
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
            &addr,
        );
        // consume(rel-ram-write-addr, write-mult, ram-init-final-addr)
        logup_trace_builder.add_to_relation_with(
            &rel_ram_write_addr,
            [write_mult],
            |[write_mult]| (-write_mult).into(),
            &addr,
        );

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [is_static_memory] =
            preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsStaticAddr);
        let addr = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Address);
        let [ram_val_init] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::InitVal);

        let [ram_val_final] = trace_eval!(trace_eval, Column::RamValFinal);
        let ram_ts_final = trace_eval!(trace_eval, Column::RamTsFinal);

        let [read_mult] = trace_eval!(trace_eval, Column::MultiplicityRead);
        let [write_mult] = trace_eval!(trace_eval, Column::MultiplicityWrite);

        // constrain multiplicities to be zeroed on padding rows
        eval.add_constraint((E::F::one() - is_static_memory.clone()) * read_mult.clone());
        eval.add_constraint((E::F::one() - is_static_memory.clone()) * write_mult.clone());

        let (rel_ram_read_write, rel_ram_read_addr, rel_ram_write_addr) = lookup_elements;

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            (-is_static_memory.clone()).into(),
            &[
                addr.as_slice(),
                std::slice::from_ref(&ram_val_final),
                &ram_ts_final,
            ]
            .concat(),
        ));
        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            is_static_memory.into(),
            &[
                addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![E::F::zero(); WORD_SIZE_HALVED].as_slice(),
            ]
            .concat(),
        ));

        // consume(rel-ram-read-addr, read-mult, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_addr,
            (-read_mult).into(),
            &addr,
        ));
        // consume(rel-ram-write-addr, write-mult, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_write_addr,
            (-write_mult).into(),
            &addr,
        ));

        eval.finalize_logup_in_pairs();
    }
}
