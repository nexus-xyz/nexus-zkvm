use num_traits::One;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::PackedBaseField, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{
    builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval, original_base_column,
    trace_eval, virtual_column::VirtualColumn,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToRamLookupElements, LogupTraceBuilder,
        RamReadWriteLookupElements, RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod ram_write_constraints;
mod timestamp_constraints;

mod columns;
mod trace;

use columns::{Column, PreprocessedColumn};

pub use columns::ShiftedBaseAddr;
pub use trace::ReadWriteMemorySideNote;

pub struct ReadWriteMemory;

impl BuiltInComponent for ReadWriteMemory {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        RamReadWriteLookupElements,
        InstToRamLookupElements,
        RangeCheckLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        trace::generate_main_trace(side_note)
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
        let (rel_ram_read_write, rel_inst_to_ram, range_check) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);
        let ram_base_addr = original_base_column!(component_trace, Column::RamBaseAddr);

        let [ram1_val_cur] = original_base_column!(component_trace, Column::Ram1ValCur);
        let [ram2_val_cur] = original_base_column!(component_trace, Column::Ram2ValCur);
        let [ram3_val_cur] = original_base_column!(component_trace, Column::Ram3ValCur);
        let [ram4_val_cur] = original_base_column!(component_trace, Column::Ram4ValCur);

        let [ram1_val_prev] = original_base_column!(component_trace, Column::Ram1ValPrev);
        let [ram2_val_prev] = original_base_column!(component_trace, Column::Ram2ValPrev);
        let [ram3_val_prev] = original_base_column!(component_trace, Column::Ram3ValPrev);
        let [ram4_val_prev] = original_base_column!(component_trace, Column::Ram4ValPrev);

        let ram1_ts_prev = original_base_column!(component_trace, Column::Ram1TsPrev);
        let ram2_ts_prev = original_base_column!(component_trace, Column::Ram2TsPrev);
        let ram3_ts_prev = original_base_column!(component_trace, Column::Ram3TsPrev);
        let ram4_ts_prev = original_base_column!(component_trace, Column::Ram4TsPrev);
        let ram1_ts_prev_aux = original_base_column!(component_trace, Column::Ram1TsPrevAux);
        let ram2_ts_prev_aux = original_base_column!(component_trace, Column::Ram2TsPrevAux);
        let ram3_ts_prev_aux = original_base_column!(component_trace, Column::Ram3TsPrevAux);
        let ram4_ts_prev_aux = original_base_column!(component_trace, Column::Ram4TsPrevAux);

        for timestamp_bytes in [
            ram1_ts_prev,
            ram1_ts_prev_aux,
            ram2_ts_prev,
            ram2_ts_prev_aux,
            ram3_ts_prev,
            ram3_ts_prev_aux,
            ram4_ts_prev,
            ram4_ts_prev_aux,
        ] {
            range_check.range256.generate_logup_col(
                &mut logup_trace_builder,
                is_local_pad.clone(),
                &timestamp_bytes,
            );
        }
        range_check.range256.generate_logup_col(
            &mut logup_trace_builder,
            is_local_pad.clone(),
            &[ram1_val_prev, ram2_val_prev, ram3_val_prev, ram4_val_prev],
        );

        let [ram1_accessed] = original_base_column!(component_trace, Column::Ram1Accessed);
        let [ram2_accessed] = original_base_column!(component_trace, Column::Ram2Accessed);
        let [ram3_4_accessed] = original_base_column!(component_trace, Column::Ram3_4Accessed);

        let [ram_write] = original_base_column!(component_trace, Column::RamWrite);
        // consume(
        //     rel-inst-to-ram,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         ram-base-addr,
        //         ram1-val-cur, ram2-val-cur, ram3-val-cur, ram4-val-cur,
        //         ram1-accessed, ram2-accessed, ram3-accessed, ram4-accessed,
        //         ram-write
        //     )
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_ram,
            [is_local_pad],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[
                clk.as_slice(),
                ram_base_addr.as_slice(),
                &[
                    ram1_val_cur,
                    ram2_val_cur,
                    ram3_val_cur,
                    ram4_val_cur,
                    ram1_accessed,
                    ram2_accessed,
                    ram3_4_accessed,
                    ram_write,
                ],
            ]
            .concat(),
        );

        // consume(rel-ram-read-write, ram{i}-accessed, (ram-base-addr, ram{i}-val-prev, ram{i}-ts-prev)) for i = 1, 2, 3, 4
        for (ram_accessed, ram_val_prev, ram_ts_prev) in [
            (
                Column::Ram1Accessed,
                Column::Ram1ValPrev,
                Column::Ram1TsPrev,
            ),
            (
                Column::Ram2Accessed,
                Column::Ram2ValPrev,
                Column::Ram2TsPrev,
            ),
            (
                Column::Ram3_4Accessed,
                Column::Ram3ValPrev,
                Column::Ram3TsPrev,
            ),
            (
                Column::Ram3_4Accessed,
                Column::Ram4ValPrev,
                Column::Ram4TsPrev,
            ),
        ] {
            ReadWriteMemory::consume_access(
                &mut logup_trace_builder,
                &component_trace,
                &rel_ram_read_write,
                ram_accessed,
                ram_val_prev,
                ram_ts_prev,
            );
        }
        // provide(rel-ram-read-write, ram{i}-accessed, (ram-base-addr, ram{i}-val-cur, clk)) for i = 1, 2, 3, 4
        for (ram_accessed, ram_val_cur) in [
            (Column::Ram1Accessed, Column::Ram1ValCur),
            (Column::Ram2Accessed, Column::Ram2ValCur),
            (Column::Ram3_4Accessed, Column::Ram3ValCur),
            (Column::Ram3_4Accessed, Column::Ram4ValCur),
        ] {
            ReadWriteMemory::provide_access(
                &mut logup_trace_builder,
                &component_trace,
                &rel_ram_read_write,
                ram_accessed,
                ram_val_cur,
            );
        }

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let (rel_ram_read_write, rel_inst_to_ram, range_check) = lookup_elements;

        ReadWriteMemory::constrain_timestamps(eval, &trace_eval, range_check);
        ReadWriteMemory::constrain_ram_write(eval, &trace_eval, range_check);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let clk = trace_eval!(trace_eval, Column::Clk);
        let ram_base_addr = trace_eval!(trace_eval, Column::RamBaseAddr);

        let [ram1_val_cur] = trace_eval!(trace_eval, Column::Ram1ValCur);
        let [ram2_val_cur] = trace_eval!(trace_eval, Column::Ram2ValCur);
        let [ram3_val_cur] = trace_eval!(trace_eval, Column::Ram3ValCur);
        let [ram4_val_cur] = trace_eval!(trace_eval, Column::Ram4ValCur);

        let [ram1_accessed] = trace_eval!(trace_eval, Column::Ram1Accessed);
        let [ram2_accessed] = trace_eval!(trace_eval, Column::Ram2Accessed);
        let [ram3_4_accessed] = trace_eval!(trace_eval, Column::Ram3_4Accessed);

        let [ram_write] = trace_eval!(trace_eval, Column::RamWrite);

        // consume(
        //     rel-inst-to-ram,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         ram-base-addr,
        //         ram1-val-cur, ram2-val-cur, ram3-val-cur, ram4-val-cur,
        //         ram1-accessed, ram2-accessed, ram3-accessed, ram4-accessed,
        //         ram-write
        //     )
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_ram,
            (is_local_pad - E::F::one()).into(),
            &[
                clk.as_slice(),
                ram_base_addr.as_slice(),
                &[
                    ram1_val_cur,
                    ram2_val_cur,
                    ram3_val_cur,
                    ram4_val_cur,
                    ram1_accessed,
                    ram2_accessed,
                    ram3_4_accessed,
                    ram_write,
                ],
            ]
            .concat(),
        ));

        // consume(rel-ram-read-write, ram{i}-accessed, (ram-base-addr, ram{i}-val-prev, ram{i}-ts-prev)) for i = 1, 2, 3, 4
        for (ram_accessed, ram_val_prev, ram_ts_prev) in [
            (
                Column::Ram1Accessed,
                Column::Ram1ValPrev,
                Column::Ram1TsPrev,
            ),
            (
                Column::Ram2Accessed,
                Column::Ram2ValPrev,
                Column::Ram2TsPrev,
            ),
            (
                Column::Ram3_4Accessed,
                Column::Ram3ValPrev,
                Column::Ram3TsPrev,
            ),
            (
                Column::Ram3_4Accessed,
                Column::Ram4ValPrev,
                Column::Ram4TsPrev,
            ),
        ] {
            ReadWriteMemory::constrain_consume_access(
                eval,
                &trace_eval,
                rel_ram_read_write,
                ram_accessed,
                ram_val_prev,
                ram_ts_prev,
            );
        }
        // provide(rel-ram-read-write, ram{i}-accessed, (ram-base-addr, ram{i}-val-cur, clk)) for i = 1, 2, 3, 4
        for (ram_accessed, ram_val_cur) in [
            (Column::Ram1Accessed, Column::Ram1ValCur),
            (Column::Ram2Accessed, Column::Ram2ValCur),
            (Column::Ram3_4Accessed, Column::Ram3ValCur),
            (Column::Ram3_4Accessed, Column::Ram4ValCur),
        ] {
            ReadWriteMemory::constrain_provide_access(
                eval,
                &trace_eval,
                rel_ram_read_write,
                ram_accessed,
                ram_val_cur,
            );
        }

        eval.finalize_logup_in_pairs();
    }
}

impl ReadWriteMemory {
    fn constrain_consume_access<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RamReadWriteLookupElements,
        ram_accessed: Column,
        ram_val_prev: Column,
        ram_ts_prev: Column,
    ) {
        let address_offset = ram_val_prev.address_offset();

        let [ram_accessed] = trace_eval.column_eval(ram_accessed);
        let mut ram_base_addr: [E::F; WORD_SIZE] = trace_eval!(trace_eval, Column::RamBaseAddr);
        let [ram_val_prev] = trace_eval.column_eval(ram_val_prev);
        let ram_ts_prev: [E::F; WORD_SIZE] = trace_eval.column_eval(ram_ts_prev);

        ram_base_addr[0] += BaseField::from(address_offset);
        let ram_ts_prev_low =
            ram_ts_prev[0].clone() + ram_ts_prev[1].clone() * BaseField::from(1 << 8);
        let ram_ts_prev_high =
            ram_ts_prev[2].clone() + ram_ts_prev[3].clone() * BaseField::from(1 << 8);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-ram_accessed).into(),
            &[
                ram_base_addr.as_slice(),
                &[ram_val_prev, ram_ts_prev_low, ram_ts_prev_high],
            ]
            .concat(),
        ));
    }

    fn constrain_provide_access<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RamReadWriteLookupElements,
        ram_accessed: Column,
        ram_val_cur: Column,
    ) {
        let address_offset = ram_val_cur.address_offset();

        let [ram_accessed] = trace_eval.column_eval(ram_accessed);
        let mut ram_base_addr: [E::F; WORD_SIZE] = trace_eval!(trace_eval, Column::RamBaseAddr);
        let [ram_val_cur] = trace_eval.column_eval(ram_val_cur);

        ram_base_addr[0] += BaseField::from(address_offset);
        let [clk_low, clk_high] = trace_eval!(trace_eval, Column::Clk);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (ram_accessed).into(),
            &[ram_base_addr.as_slice(), &[ram_val_cur, clk_low, clk_high]].concat(),
        ));
    }

    fn consume_access(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        lookup_elements: &RamReadWriteLookupElements,
        ram_accessed: Column,
        ram_val_prev: Column,
        ram_ts_prev: Column,
    ) {
        let address_offset = ram_val_prev.address_offset();

        let [ram_accessed] = component_trace.original_base_column(ram_accessed);
        let ram_base_addr: [_; WORD_SIZE] =
            original_base_column!(component_trace, Column::RamBaseAddr);
        let [ram_val_prev] = component_trace.original_base_column(ram_val_prev);

        let ram_base_addr_0 = ShiftedBaseAddr {
            column: Column::RamBaseAddr,
            offset: address_offset,
        };
        let ram_base_addr_0 = ram_base_addr_0.combine_from_finalized_trace(component_trace);

        let ram_ts_prev_low = HalfWord {
            col: ram_ts_prev,
            idx: 0,
        };
        let ram_ts_prev_high = HalfWord {
            col: ram_ts_prev,
            idx: 1,
        };

        let ram_ts_prev_low = ram_ts_prev_low.combine_from_finalized_trace(component_trace);
        let ram_ts_prev_high = ram_ts_prev_high.combine_from_finalized_trace(component_trace);

        logup_trace_builder.add_to_relation_with(
            lookup_elements,
            [ram_accessed],
            |[ram_accessed]| (-ram_accessed).into(),
            &[
                std::slice::from_ref(&ram_base_addr_0),
                &ram_base_addr[1..],
                &[ram_val_prev, ram_ts_prev_low, ram_ts_prev_high],
            ]
            .concat(),
        );
    }

    fn provide_access(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        lookup_elements: &RamReadWriteLookupElements,
        ram_accessed: Column,
        ram_val_cur: Column,
    ) {
        let address_offset = ram_val_cur.address_offset();

        let [ram_accessed] = component_trace.original_base_column(ram_accessed);
        let ram_base_addr: [_; WORD_SIZE] =
            original_base_column!(component_trace, Column::RamBaseAddr);
        let [ram_val_cur] = component_trace.original_base_column(ram_val_cur);

        let ram_base_addr_0 = ShiftedBaseAddr {
            column: Column::RamBaseAddr,
            offset: address_offset,
        };
        let ram_base_addr_0 = ram_base_addr_0.combine_from_finalized_trace(component_trace);
        let [clk_low, clk_high] = original_base_column!(component_trace, Column::Clk);

        logup_trace_builder.add_to_relation(
            lookup_elements,
            ram_accessed,
            &[
                std::slice::from_ref(&ram_base_addr_0),
                &ram_base_addr[1..],
                &[ram_val_cur, clk_low, clk_high],
            ]
            .concat(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use stwo::core::fields::{m31::BaseField, FieldExpOps};
    use stwo_constraint_framework::Relation;

    use crate::{
        components::{read_write_memory_boundary::PrivateMemoryBoundary, RANGE256},
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
        lookups::RamWriteAddressLookupElements,
        verify::verify_logup_sum,
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
        let mut claimed_sum = assert_component(ReadWriteMemory, assert_ctx);

        claimed_sum += components_claimed_sum(&[&PrivateMemoryBoundary, &RANGE256], assert_ctx);
        // manually add a fraction from the store component to skip registers and cpu
        //
        // (
        //     clk,
        //     ram-base-addr,
        //     ram1-val-cur, ram2-val-cur, ram3-val-cur, ram4-val-cur,
        //     ram1-accessed, ram2-accessed, ram3-accessed, ram4-accessed,
        //     ram-write
        // )
        let lookup_elements: &InstToRamLookupElements = assert_ctx.lookup_elements.as_ref();
        let tuple = [
            [5u8, 0].as_slice(),                                // clk
            (0x80008u32 - 0x80000u32).to_le_bytes().as_slice(), // ram-base-addr
            &[128, 0, 0, 0],                                    // ram-val-cur
            &[1, 0, 0],                                         // ram-accessed
            &[1],                                               // ram-write
        ]
        .concat();
        let m31_tuple: Vec<BaseField> = tuple
            .into_iter()
            .map(|byte| BaseField::from(byte as u32))
            .collect();
        claimed_sum += <InstToRamLookupElements as Relation<BaseField, SecureField>>::combine(
            lookup_elements,
            &m31_tuple,
        )
        .inverse();

        // add address to the write set
        let rel_write_addrs: &RamWriteAddressLookupElements = assert_ctx.lookup_elements.as_ref();
        let addr_tuple: Vec<BaseField> = (0x80008u32 - 0x80000u32)
            .to_le_bytes()
            .into_iter()
            .map(|byte| BaseField::from(byte as u32))
            .collect();
        claimed_sum +=
            <RamWriteAddressLookupElements as Relation<BaseField, SecureField>>::combine(
                rel_write_addrs,
                &addr_tuple,
            )
            .inverse();
        verify_logup_sum(&[claimed_sum], &view, &assert_ctx.lookup_elements).unwrap();
    }
}
