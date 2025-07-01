//! Helper component needed to eliminate boundary logup terms in the read-write memory component.

use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        fields::{
            m31::{self, BaseField},
            qm31::SecureField,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{
    emulator::{MemoryInitializationEntry, PublicOutputEntry},
    WORD_SIZE,
};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    original_base_column, preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, RamReadWriteLookupElements},
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct ReadWriteMemoryBoundary;

impl ReadWriteMemoryBoundary {
    // Computes ram-val-init column from the finalized preprocessed trace
    fn combine_ram_val_init(component_trace: &ComponentTrace) -> FinalizedColumn {
        let [pub_in_flag] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::PubInFlag);
        let [pub_in_val] = preprocessed_base_column!(component_trace, PreprocessedColumn::PubInVal);

        let log_size = component_trace.log_size();
        let mut col = Vec::with_capacity((log_size - LOG_N_LANES) as usize);
        for vec_idx in 0..1 << (log_size - LOG_N_LANES) {
            col.push(pub_in_flag.at(vec_idx) * pub_in_val.at(vec_idx));
        }
        FinalizedColumn::new_virtual(BaseColumn::from_simd(col))
    }
}

impl BuiltInComponent for ReadWriteMemoryBoundary {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = RamReadWriteLookupElements;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        program_ref: &ProgramTraceRef,
    ) -> FinalizedTrace {
        let mut trace = TraceBuilder::new(log_size);

        let init_memory = program_ref.init_memory;
        let exit_code = program_ref.exit_code;
        let output_memory = program_ref.public_output;

        let init_memory_len = init_memory.len();
        let exit_code_len = exit_code.len();

        for (row_idx, MemoryInitializationEntry { address, value }) in
            init_memory.iter().enumerate()
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
        for (row_idx, PublicOutputEntry { address, value }) in output_memory.iter().enumerate() {
            let row_idx = row_idx + offset;
            trace.fill_columns(row_idx, *address, PreprocessedColumn::PubIoAddr);

            trace.fill_columns(row_idx, true, PreprocessedColumn::PubOutFlag);
            trace.fill_columns(row_idx, *value, PreprocessedColumn::PubOutVal);
        }
        trace.finalize()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let last_access = side_note.memory.read_write_memory.last_access();
        let log_size = last_access
            .len()
            .next_power_of_two()
            .ilog2()
            .max(LOG_N_LANES);

        let mut trace = TraceBuilder::new(log_size);
        for (row_idx, (address, (last_access, last_value))) in last_access.iter().enumerate() {
            trace.fill_columns(row_idx, *address, Column::RamInitFinalAddr);
            trace.fill_columns(row_idx, true, Column::RamInitFinalFlag);
            assert!(*last_access < m31::P, "Access counter overflow");

            trace.fill_columns(row_idx, *last_access, Column::RamTsFinal);
            trace.fill_columns(row_idx, *last_value, Column::RamValFinal);
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
        let rel_ram_read_write: &Self::LookupElements = lookup_elements.as_ref();
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [ram_init_final_flag] =
            original_base_column!(component_trace, Column::RamInitFinalFlag);
        let ram_init_final_addr = original_base_column!(component_trace, Column::RamInitFinalAddr);
        let [ram_val_final] = original_base_column!(component_trace, Column::RamValFinal);
        let ram_ts_final = original_base_column!(component_trace, Column::RamTsFinal);

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        logup_trace_builder.add_to_relation_with(
            rel_ram_read_write,
            [ram_init_final_flag.clone()],
            |[ram_init_final_flag]| (-ram_init_final_flag).into(),
            &[
                ram_init_final_addr.as_slice(),
                std::slice::from_ref(&ram_val_final),
                &ram_ts_final,
            ]
            .concat(),
        );

        let ram_val_init = ReadWriteMemoryBoundary::combine_ram_val_init(&component_trace);
        // provide(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-init, 0))
        logup_trace_builder.add_to_relation(
            rel_ram_read_write,
            ram_init_final_flag,
            &[
                ram_init_final_addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![BaseField::zero().into(); WORD_SIZE].as_slice(),
            ]
            .concat(),
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        // TODO: constrain uniqueness of witness addresses.

        let [pub_in_flag] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubInFlag);
        let [pub_out_flag] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubOutFlag);

        let ram_init_final_addr: [E::F; WORD_SIZE] =
            trace_eval!(trace_eval, Column::RamInitFinalAddr);
        let pub_io_addr: [E::F; WORD_SIZE] =
            preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubIoAddr);

        let [ram_val_final] = trace_eval!(trace_eval, Column::RamValFinal);
        let [pub_in_val] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubInVal);
        let [pub_out_val] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PubOutVal);

        let ram_val_init = pub_in_flag.clone() * pub_in_val.clone();

        // (pub-in-flag + pub-out-flag) · (ram-init-final-addr(i) − pub-io-addr(i)) = 0 for i = 1, 2, 3, 4
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                (pub_in_flag.clone() + pub_out_flag.clone())
                    * (ram_init_final_addr[i].clone() - pub_io_addr[i].clone()),
            );
        }

        // ram-val-final = pub-out-val when pub-out-flag = 1
        eval.add_constraint(pub_out_flag * (ram_val_final.clone() - pub_out_val));
        // ram-val-init = pub-in-flag · pub-in-val
        eval.add_constraint(pub_in_flag.clone() * pub_in_val.clone() - ram_val_init.clone());

        let rel_ram_read_write = lookup_elements;
        let [ram_init_final_flag] = trace_eval!(trace_eval, Column::RamInitFinalFlag);
        let ram_ts_final = trace_eval!(trace_eval, Column::RamTsFinal);

        // consume(rel-ram-read-write, ram-init-final-flag, (ram-init-final-addr, ram-val-final, ram-ts-final))
        eval.add_to_relation(RelationEntry::new(
            rel_ram_read_write,
            (-ram_init_final_flag.clone()).into(),
            &[
                ram_init_final_addr.as_slice(),
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
                ram_init_final_addr.as_slice(),
                std::slice::from_ref(&ram_val_init),
                vec![E::F::zero(); WORD_SIZE].as_slice(),
            ]
            .concat(),
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
        let _claimed_sum = assert_component(ReadWriteMemoryBoundary, assert_ctx);
    }
}
