//! Helper component needed to eliminate boundary logup terms in the read-write memory component.

use num_traits::Zero;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_vm::{emulator::ProgramMemoryEntry, WORD_SIZE};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column, preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    components::utils::u32_to_16bit_parts_le,
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, ProgramMemoryReadLookupElements},
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct ProgramMemoryBoundary;

impl BuiltInComponent for ProgramMemoryBoundary {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = ProgramMemoryReadLookupElements;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        let program_memory = &program.program_memory.program;

        let program_memory_log_size = program_memory
            .len()
            .next_power_of_two()
            .ilog2()
            .max(LOG_N_LANES);
        assert_eq!(program_memory_log_size, log_size);

        let mut trace = TraceBuilder::new(log_size);
        for (
            row_idx,
            ProgramMemoryEntry {
                pc,
                instruction_word,
            },
        ) in program_memory.iter().enumerate()
        {
            let pc_parts = u32_to_16bit_parts_le(*pc);
            let instr_parts = u32_to_16bit_parts_le(*instruction_word);
            trace.fill_columns(row_idx, pc_parts, PreprocessedColumn::ProgInitBaseAddr);
            trace.fill_columns(row_idx, instr_parts, PreprocessedColumn::ProgValInit);
            trace.fill_columns(row_idx, true, PreprocessedColumn::ProgInitFlag);
        }
        trace.finalize()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let program_ref = &side_note.program;
        let program_memory = &program_ref.program_memory.program;
        let pc_offset = program_memory[0].pc;
        let program_len = program_memory.len();

        let log_size = program_len.next_power_of_two().ilog2().max(LOG_N_LANES);
        let mut trace = TraceBuilder::new(log_size);
        for (pc, final_counter) in side_note.memory.program_memory.last_access() {
            assert!(*pc >= pc_offset);

            let pc = (pc - pc_offset) as usize;
            assert!(pc.is_multiple_of(WORD_SIZE));

            let row_idx = pc / WORD_SIZE;
            assert!(row_idx < program_len);

            trace.fill_columns(row_idx, *final_counter, Column::ProgCtrFinal);
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
        let rel_prog_memory_read: &Self::LookupElements = lookup_elements.as_ref();
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [prog_init_flag] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::ProgInitFlag);
        let prog_init_base_addr =
            preprocessed_base_column!(component_trace, PreprocessedColumn::ProgInitBaseAddr);
        let prog_val_init =
            preprocessed_base_column!(component_trace, PreprocessedColumn::ProgValInit);

        let prog_ctr_final = original_base_column!(component_trace, Column::ProgCtrFinal);

        // consume(rel-prog-memory-read, prog-init-flag, (prog-init-base-addr, prog-val-init, prog-ctr-final))
        logup_trace_builder.add_to_relation_with(
            rel_prog_memory_read,
            [prog_init_flag.clone()],
            |[prog_init_flag]| (-prog_init_flag).into(),
            &[
                prog_init_base_addr.as_slice(),
                &prog_val_init,
                &prog_ctr_final,
            ]
            .concat(),
        );

        // provide(rel-prog-memory-read, prog-init-flag, (prog-init-base-addr, prog-val-init, 0))
        logup_trace_builder.add_to_relation(
            rel_prog_memory_read,
            prog_init_flag,
            &[
                prog_init_base_addr.as_slice(),
                &prog_val_init,
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
        let [prog_init_flag] =
            preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ProgInitFlag);
        let prog_init_base_addr =
            preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ProgInitBaseAddr);
        let prog_val_init = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ProgValInit);

        let prog_ctr_final = trace_eval!(trace_eval, Column::ProgCtrFinal);

        let rel_prog_memory_read = lookup_elements;

        // consume(rel-prog-memory-read, prog-init-flag, (prog-init-base-addr, prog-val-init, prog-ctr-final))
        eval.add_to_relation(RelationEntry::new(
            rel_prog_memory_read,
            (-prog_init_flag.clone()).into(),
            &[
                prog_init_base_addr.as_slice(),
                &prog_val_init,
                &prog_ctr_final,
            ]
            .concat(),
        ));
        // provide(rel-prog-memory-read, prog-init-flag, (prog-init-base-addr, prog-val-init, 0))
        eval.add_to_relation(RelationEntry::new(
            rel_prog_memory_read,
            prog_init_flag.into(),
            &[
                prog_init_base_addr.as_slice(),
                &prog_val_init,
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
        components::ProgramMemory,
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    #[test]
    fn assert_program_memory_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let _ = components_claimed_sum(&[&ProgramMemory], assert_ctx);
        let _claimed_sum = assert_component(ProgramMemoryBoundary, assert_ctx);
    }
}
