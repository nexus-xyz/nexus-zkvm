use num_traits::One;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{m31::PackedBaseField, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm_prover_trace::{
    builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval, original_base_column,
    trace_eval, virtual_column::VirtualColumn,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        LogupTraceBuilder, ProgramMemoryReadLookupElements, RangeCheckLookupElements,
        RangeLookupBound,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
mod trace;

use columns::{Column, PreprocessedColumn, PC_HIGH, PC_LOW};
pub use trace::ProgramMemorySideNote;

pub struct ProgramMemory;

impl BuiltInComponent for ProgramMemory {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        ProgramMemoryReadLookupElements,
        InstToProgMemoryLookupElements,
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
        let (rel_prog_memory_read, rel_inst_to_prog_memory, range_check) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let pc = original_base_column!(component_trace, Column::Pc);
        let instr_val = original_base_column!(component_trace, Column::InstrVal);

        let prog_ctr_cur = original_base_column!(component_trace, Column::ProgCtrCur);
        let prog_ctr_prev = original_base_column!(component_trace, Column::ProgCtrPrev);

        let pc_low = PC_LOW.combine_from_finalized_trace(&component_trace);
        let pc_high = PC_HIGH.combine_from_finalized_trace(&component_trace);

        for timestamp_bytes in [&prog_ctr_prev, &prog_ctr_cur] {
            for byte in timestamp_bytes {
                range_check.range256.generate_logup_col(
                    &mut logup_trace_builder,
                    is_local_pad.clone(),
                    byte.clone(),
                );
            }
        }

        // provide(rel-inst-to-prog-memory, 1 − is-local-pad, (pc, instr-val))
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_prog_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[[pc_low, pc_high].as_slice(), &instr_val].concat(),
        );
        // consume(rel-prog-memory-read, 1 − is-local-pad, (pc, instr-val, prog-ctr-prev))
        logup_trace_builder.add_to_relation_with(
            &rel_prog_memory_read,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[pc.as_slice(), &instr_val, &prog_ctr_prev].concat(),
        );
        // provide(rel-prog-memory-read, 1 − is-local-pad, (pc, instr-val, prog-ctr-cur))
        logup_trace_builder.add_to_relation_with(
            &rel_prog_memory_read,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[pc.as_slice(), &instr_val, &prog_ctr_cur].concat(),
        );

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let instr_val = trace_eval!(trace_eval, Column::InstrVal);

        let prog_ctr_cur = trace_eval!(trace_eval, Column::ProgCtrCur);
        let prog_ctr_prev = trace_eval!(trace_eval, Column::ProgCtrPrev);

        let [prog_ctr_carry] = trace_eval!(trace_eval, Column::ProgCtrCarry);

        // (1 − is-local-pad) · (prog-ctr-cur(1) + prog-ctr-cur(2) · 2^8 + prog-ctr-carry(1) · 2^16
        //     − prog-ctr-prev(1) − prog-ctr-prev(2) · 2^8 − 1) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (prog_ctr_cur[0].clone()
                    + prog_ctr_cur[1].clone() * BaseField::from(1 << 8)
                    + prog_ctr_carry.clone() * BaseField::from(1 << 16)
                    - (prog_ctr_prev[0].clone()
                        + prog_ctr_prev[1].clone() * BaseField::from(1 << 8)
                        + E::F::one())),
        );

        // prog-ctr-carry(2) is constrained to equal 0 and is replaced with a constant.
        //
        // (1 − is-local-pad) · (prog-ctr-cur(3) + prog-ctr-cur(4) · 2^8 + prog-ctr-carry(2) · 2^16
        //     − prog-ctr-prev(1) − prog-ctr-prev(2) · 2^8 − prog-ctr-carry(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (prog_ctr_cur[2].clone() + prog_ctr_cur[3].clone() * BaseField::from(1 << 8)
                    - (prog_ctr_prev[2].clone()
                        + prog_ctr_prev[3].clone() * BaseField::from(1 << 8)
                        + prog_ctr_carry.clone())),
        );

        // prog-ctr-carry(j) ∈ {0, 1} for j = 1, 2
        eval.add_constraint(prog_ctr_carry.clone() * (E::F::one() - prog_ctr_carry));

        let pc_low = PC_LOW.eval(&trace_eval);
        let pc_high = PC_HIGH.eval(&trace_eval);

        let (rel_prog_memory_read, rel_inst_to_prog_memory, range_check) = lookup_elements;
        for timestamp_bytes in [&prog_ctr_prev, &prog_ctr_cur] {
            for byte in timestamp_bytes {
                range_check
                    .range256
                    .constrain(eval, is_local_pad.clone(), byte.clone());
            }
        }
        // provide(rel-inst-to-prog-memory, 1 − is-local-pad, (pc, instr-val))
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_prog_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[[pc_low, pc_high].as_slice(), &instr_val].concat(),
        ));
        // consume(rel-prog-memory-read, 1 − is-local-pad, (pc, instr-val, prog-ctr-prev))
        eval.add_to_relation(RelationEntry::new(
            rel_prog_memory_read,
            (is_local_pad.clone() - E::F::one()).into(),
            &[pc.as_slice(), &instr_val, &prog_ctr_prev].concat(),
        ));
        // provide(rel-prog-memory-read, 1 − is-local-pad, (pc, instr-val, prog-ctr-cur))
        eval.add_to_relation(RelationEntry::new(
            rel_prog_memory_read,
            (E::F::one() - is_local_pad).into(),
            &[pc.as_slice(), &instr_val, &prog_ctr_cur].concat(),
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            program_memory_boundary::ProgramMemoryBoundary, Cpu, CpuBoundary, RegisterMemory,
            RegisterMemoryBoundary, ADDI, RANGE16, RANGE256, RANGE64, RANGE8,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_program_memory_constraints() {
        let basic_block = vec![BasicBlock::new(vec![Instruction::new_ir(
            Opcode::from(BuiltinOpcode::ADDI),
            1,
            0,
            1,
        )])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(ProgramMemory, assert_ctx);
        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &ADDI,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemoryBoundary,
                &RANGE8,
                &RANGE16,
                &RANGE64,
                &RANGE256,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
