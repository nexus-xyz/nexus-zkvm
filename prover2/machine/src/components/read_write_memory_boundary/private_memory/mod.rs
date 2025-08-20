//! Helper component for private access of heap_start..stack_top memory.

use std::collections::BTreeMap;

use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        ColumnVec,
    },
    prover::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, Relation, RelationEntry};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column, trace_eval,
};

use crate::{
    components::utils::{subtract_with_borrow, u32_to_16bit_parts_le},
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, LogupTraceBuilder,
        RamReadAddressLookupElements, RamReadWriteLookupElements, RamUniqueAddrLookupElements,
        RamWriteAddressLookupElements, RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, range_check::Range256Multiplicities, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct PrivateMemoryBoundary;

impl PrivateMemoryBoundary {
    pub fn expected_logup_sum(
        program: &ProgramTraceRef,
        lookup_elements: &RamUniqueAddrLookupElements,
    ) -> SecureField {
        let memory_start = program.private_memory_start;
        let memory_end = program.private_memory_end;
        if memory_start == memory_end {
            SecureField::zero()
        } else {
            let start_bytes: Vec<BaseField> = memory_start
                .to_le_bytes()
                .into_iter()
                .map(|byte| BaseField::from(byte as u32))
                .collect();
            let end_bytes: Vec<BaseField> = memory_end
                .to_le_bytes()
                .into_iter()
                .map(|byte| BaseField::from(byte as u32))
                .collect();

            let start: SecureField = lookup_elements.combine(&start_bytes);
            let end: SecureField = lookup_elements.combine(&end_bytes);

            end.inverse() - start.inverse()
        }
    }
}

impl BuiltInComponent for PrivateMemoryBoundary {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        RamReadWriteLookupElements,
        RamUniqueAddrLookupElements,
        RamReadAddressLookupElements,
        RamWriteAddressLookupElements,
        RangeCheckLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program_ref: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let memory_start = side_note.program.private_memory_start;
        let memory_end = side_note.program.private_memory_end;
        assert!(memory_start <= memory_end);

        let last_access = side_note.memory.read_write_memory.last_access();
        let read_mults: &BTreeMap<u32, u32> = &side_note.memory.read_access;
        let write_mults: &BTreeMap<u32, u32> = &side_note.memory.write_access;

        let mut access_iter = last_access.range(memory_start..);

        if memory_start == memory_end {
            assert!(access_iter.next().is_none(), "invalid memory access");
            return TraceBuilder::<Column>::new(LOG_N_LANES).finalize();
        }

        let len = access_iter.clone().count();
        let log_size = len.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut trace = TraceBuilder::new(log_size);
        let mut range256_mults = Range256Multiplicities::default();

        let mut curr_addr = if last_access.contains_key(&memory_start) {
            access_iter.next().expect("access is non-empty")
        } else {
            (&memory_start, &(0, 0))
        };

        let mut row_idx = 0;
        while curr_addr.0 < &memory_end {
            let next_addr = access_iter.next().unwrap_or((&memory_end, &(0, 0)));

            let curr_addr_bytes = curr_addr.0.to_le_bytes();
            let next_addr_bytes = next_addr.0.to_le_bytes();

            let (diff, borrow) = subtract_with_borrow(curr_addr_bytes, next_addr_bytes);
            assert!(borrow[3]);

            trace.fill_columns(row_idx, curr_addr_bytes, Column::CurrAddress);
            trace.fill_columns(row_idx, next_addr_bytes, Column::NextAddress);
            trace.fill_columns(row_idx, diff, Column::Diff);
            trace.fill_columns(row_idx, borrow[1], Column::Borrow);

            let (final_ts, final_val) = curr_addr.1;
            let final_ts = u32_to_16bit_parts_le(*final_ts);
            trace.fill_columns(row_idx, final_ts, Column::RamTsFinal);
            trace.fill_columns(row_idx, *final_val, Column::RamValFinal);

            let read_mult = read_mults.get(curr_addr.0).copied().unwrap_or_default();
            let write_mult = write_mults.get(curr_addr.0).copied().unwrap_or_default();
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

            range256_mults.add_values(&curr_addr_bytes);
            range256_mults.add_values(&diff);

            curr_addr = next_addr;
            row_idx += 1;
        }
        for row in row_idx..1 << log_size {
            trace.fill_columns(row, true, Column::IsPad);
        }
        side_note.range_check.range256.append(range256_mults);

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
        let (
            rel_ram_read_write,
            rel_ram_unique_addr,
            rel_ram_read_addr,
            rel_ram_write_addr,
            range_check,
        ) = Self::LookupElements::get(lookup_elements);
        let log_size = component_trace.log_size();
        let mut logup_trace_builder = LogupTraceBuilder::new(log_size);

        let [is_pad] = original_base_column!(component_trace, Column::IsPad);
        let addr = original_base_column!(component_trace, Column::CurrAddress);
        let next_addr = original_base_column!(component_trace, Column::NextAddress);
        let diff = original_base_column!(component_trace, Column::Diff);
        let ram_val_init = BaseField::zero().into();

        let [ram_val_final] = original_base_column!(component_trace, Column::RamValFinal);
        let ram_ts_final = original_base_column!(component_trace, Column::RamTsFinal);

        let [read_mult] = original_base_column!(component_trace, Column::MultiplicityRead);
        let [write_mult] = original_base_column!(component_trace, Column::MultiplicityWrite);

        range_check
            .range256
            .generate_logup_col(&mut logup_trace_builder, is_pad.clone(), &addr);
        range_check
            .range256
            .generate_logup_col(&mut logup_trace_builder, is_pad.clone(), &diff);

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        logup_trace_builder.add_to_relation_with(
            &rel_ram_read_write,
            [is_pad.clone()],
            |[is_pad]| (is_pad - PackedBaseField::one()).into(),
            &[
                addr.as_slice(),
                std::slice::from_ref(&ram_val_final),
                &ram_ts_final,
            ]
            .concat(),
        );

        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        logup_trace_builder.add_to_relation_with(
            &rel_ram_read_write,
            [is_pad.clone()],
            |[is_pad]| (PackedBaseField::one() - is_pad).into(),
            &[
                addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![BaseField::zero().into(); WORD_SIZE_HALVED].as_slice(),
            ]
            .concat(),
        );

        // consume(rel-ram-unique-addr, ram-init-final-flag, ram-init-final-addr)
        logup_trace_builder.add_to_relation_with(
            &rel_ram_unique_addr,
            [is_pad.clone()],
            |[is_pad]| (is_pad - PackedBaseField::one()).into(),
            &addr,
        );
        // provide(rel-ram-unique-addr, ram-init-final-flag, ram-init-final-addr-next)
        logup_trace_builder.add_to_relation_with(
            &rel_ram_unique_addr,
            [is_pad.clone()],
            |[is_pad]| (PackedBaseField::one() - is_pad).into(),
            &next_addr,
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
        // ram-init-final-flag = 1 - is_pad
        let [is_pad] = trace_eval!(trace_eval, Column::IsPad);
        let curr_addr = trace_eval!(trace_eval, Column::CurrAddress);
        let next_addr = trace_eval!(trace_eval, Column::NextAddress);
        let ram_val_init = E::F::zero();

        let diff = trace_eval!(trace_eval, Column::Diff);
        let [borrow] = trace_eval!(trace_eval, Column::Borrow);

        // enforce that curr_addr < next_addr
        //
        // curr_addr_low + diff_low = next_addr_low + 2^16 * borrow
        eval.add_constraint(
            (E::F::one() - is_pad.clone())
                * (next_addr[0].clone()
                    + next_addr[1].clone() * BaseField::from(1 << 8)
                    + diff[0].clone()
                    + diff[1].clone() * BaseField::from(1 << 8)
                    - (curr_addr[0].clone()
                        + curr_addr[1].clone() * BaseField::from(1 << 8)
                        + borrow.clone() * BaseField::from(1 << 16))),
        );
        // curr_addr_high + borrow + diff_high = next_addr_high + 2^16
        eval.add_constraint(
            (E::F::one() - is_pad.clone())
                * (next_addr[2].clone()
                    + next_addr[3].clone() * BaseField::from(1 << 8)
                    + borrow.clone()
                    + diff[2].clone()
                    + diff[3].clone() * BaseField::from(1 << 8)
                    - (curr_addr[2].clone()
                        + curr_addr[3].clone() * BaseField::from(1 << 8)
                        + E::F::from(BaseField::from(1 << 16)))),
        );
        // borrow · (1 − borrow) = 0
        eval.add_constraint(borrow.clone() * (E::F::one() - borrow));
        // ram-init-final-flag · (1 − ram-init-final-flag) = 0
        eval.add_constraint(is_pad.clone() * (E::F::one() - is_pad.clone()));

        let [ram_val_final] = trace_eval!(trace_eval, Column::RamValFinal);
        let ram_ts_final = trace_eval!(trace_eval, Column::RamTsFinal);

        let [read_mult] = trace_eval!(trace_eval, Column::MultiplicityRead);
        let [write_mult] = trace_eval!(trace_eval, Column::MultiplicityWrite);

        // constrain multiplicities to be zeroed on padding rows
        eval.add_constraint(is_pad.clone() * read_mult.clone());
        eval.add_constraint(is_pad.clone() * write_mult.clone());

        let (
            rel_ram_read_write,
            rel_ram_unique_addr,
            rel_ram_read_addr,
            rel_ram_write_addr,
            range_check,
        ) = lookup_elements;

        range_check
            .range256
            .constrain(eval, is_pad.clone(), &curr_addr);
        range_check.range256.constrain(eval, is_pad.clone(), &diff);

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            (is_pad.clone() - E::F::one()).into(),
            &[
                curr_addr.as_slice(),
                std::slice::from_ref(&ram_val_final),
                &ram_ts_final,
            ]
            .concat(),
        ));
        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            (E::F::one() - is_pad.clone()).into(),
            &[
                curr_addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![E::F::zero(); WORD_SIZE_HALVED].as_slice(),
            ]
            .concat(),
        ));

        // consume(rel-ram-unique-addr, ram-init-final-flag, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_unique_addr,
            (is_pad.clone() - E::F::one()).into(),
            &curr_addr,
        ));
        // provide(rel-ram-unique-addr, ram-init-final-flag, ram-init-final-addr-next)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_unique_addr,
            (E::F::one() - is_pad.clone()).into(),
            &next_addr,
        ));

        // consume(rel-ram-read-addr, read-mult, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_addr,
            (-read_mult).into(),
            &curr_addr,
        ));
        // consume(rel-ram-write-addr, write-mult, ram-init-final-addr)
        eval.add_to_relation(RelationEntry::new(
            rel_ram_write_addr,
            (-write_mult).into(),
            &curr_addr,
        ));

        eval.finalize_logup_in_pairs();
    }
}
