//! Helper component needed to eliminate boundary logup terms in the register memory component.

use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{column::BaseColumn, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_common::constants::NUM_REGISTERS;
use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    original_base_column, preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, RegisterMemoryLookupElements},
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct RegisterMemoryBoundary;

impl RegisterMemoryBoundary {
    const LOG_SIZE: u32 = NUM_REGISTERS.ilog2();
}

impl BuiltInComponent for RegisterMemoryBoundary {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = RegisterMemoryLookupElements;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        let reg_col = BaseColumn::from_iter((0..1 << Self::LOG_SIZE).map(BaseField::from));
        FinalizedTrace {
            cols: vec![reg_col],
            log_size: Self::LOG_SIZE,
        }
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let register_memory = &side_note.memory.register_memory;
        let mut trace = TraceBuilder::new(Self::LOG_SIZE);

        let final_ts = register_memory.timestamps();
        let final_values = register_memory.values();
        for reg_idx in 0..NUM_REGISTERS as usize {
            trace.fill_columns(reg_idx, final_values[reg_idx], Column::FinalVal);
            trace.fill_columns(reg_idx, final_ts[reg_idx], Column::FinalTs);
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
        let rel_reg_memory_read_write: &Self::LookupElements = lookup_elements.as_ref();
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [reg_addr] = preprocessed_base_column!(component_trace, PreprocessedColumn::RegAddr);
        let reg_val_final = original_base_column!(component_trace, Column::FinalVal);
        let reg_ts_final = original_base_column!(component_trace, Column::FinalTs);

        // consume(rel-reg-memory-read-write, is-reg-addr, (reg-init-final-addr, reg-val-final, reg-ts-final))
        logup_trace_builder.add_to_relation(
            rel_reg_memory_read_write,
            -BaseField::one(),
            &[
                std::slice::from_ref(&reg_addr),
                &reg_val_final,
                &reg_ts_final,
            ]
            .concat(),
        );

        let zero_word = vec![FinalizedColumn::from(BaseField::zero()); WORD_SIZE];
        // provide(rel-reg-memory-read-write, is-reg-addr, (reg-init-final-addr, 0, 0))
        logup_trace_builder.add_to_relation(
            rel_reg_memory_read_write,
            BaseField::one(),
            &[std::slice::from_ref(&reg_addr), &zero_word, &zero_word].concat(),
        );

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [reg_addr] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegAddr);
        let reg_val_final = trace_eval!(trace_eval, Column::FinalVal);
        let reg_ts_final = trace_eval!(trace_eval, Column::FinalTs);

        let rel_reg_memory_read_write = lookup_elements;

        // consume(rel-reg-memory-read-write, is-reg-addr, (reg-init-final-addr, reg-val-final, reg-ts-final))
        eval.add_to_relation(RelationEntry::new(
            rel_reg_memory_read_write,
            -E::EF::one(),
            &[
                std::slice::from_ref(&reg_addr),
                &reg_val_final,
                &reg_ts_final,
            ]
            .concat(),
        ));

        let zero_word = vec![E::F::zero(); WORD_SIZE];
        // provide(rel-reg-memory-read-write, is-reg-addr, (reg-init-final-addr, 0, 0))
        eval.add_to_relation(RelationEntry::new(
            rel_reg_memory_read_write,
            E::EF::one(),
            &[std::slice::from_ref(&reg_addr), &zero_word, &zero_word].concat(),
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::RegisterMemory,
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    #[test]
    fn assert_register_mem_boundary_constraints() {
        let basic_block = vec![BasicBlock::new(vec![Instruction::new_ir(
            Opcode::from(BuiltinOpcode::ADDI),
            2,
            1,
            0,
        )])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        // compute final values
        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let _ = components_claimed_sum(&[&RegisterMemory], assert_ctx);

        assert_component(RegisterMemoryBoundary, assert_ctx);
    }
}
