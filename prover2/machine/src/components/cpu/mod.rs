use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{column::BaseColumn, m31::PackedBaseField, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm_prover_trace::{
    builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval, original_base_column,
    preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements, RangeCheckLookupElements, RangeLookupBound,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
mod trace;

pub use self::{columns::HalfWord, trace::preprocessed_clk_trace};
use columns::{Column, PreprocessedColumn};

pub struct Cpu;

impl BuiltInComponent for Cpu {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (ProgramExecutionLookupElements, RangeCheckLookupElements);

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        let cols = preprocessed_clk_trace(log_size);
        FinalizedTrace { cols, log_size }
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        trace::generate_main_trace(side_note)
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
        let (rel_cont_prog_exec, range_check) = Self::LookupElements::get(lookup_elements);
        let log_size = component_trace.log_size();
        let mut logup_trace_builder = LogupTraceBuilder::new(log_size);

        let [is_pad] = original_base_column!(component_trace, Column::IsPad);
        let [pc_aux] = original_base_column!(component_trace, Column::PcAux);
        let [pc8_15] = original_base_column!(component_trace, Column::PcNext8_15);

        let [pc_high] = original_base_column!(component_trace, Column::PcHigh);
        // pc-low is not part of the prover trace
        let pc_low = BaseColumn::from_iter(
            side_note
                .iter_program_steps()
                .map(|program_step| program_step.step.pc & 0xFFFF)
                .map(BaseField::from)
                .chain(std::iter::repeat(Zero::zero()))
                .take(1 << log_size),
        );

        range_check
            .range64
            .generate_logup_col(&mut logup_trace_builder, is_pad.clone(), pc_aux);
        range_check
            .range256
            .generate_logup_col(&mut logup_trace_builder, is_pad.clone(), pc8_15);

        let [clk_low, clk_high] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::Clk);

        // consume(rel-cont-prog-exec, 1 − is-pad, (clk, pc))
        logup_trace_builder.add_to_relation_with(
            &rel_cont_prog_exec,
            [is_pad.clone()],
            |[is_pad]| (is_pad - PackedBaseField::one()).into(),
            &[
                clk_low.clone(),
                clk_high.clone(),
                (&pc_low).into(),
                pc_high.clone(),
            ],
        );

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [is_pad] = trace_eval!(trace_eval, Column::IsPad);

        let [pc_aux] = trace_eval!(trace_eval, Column::PcAux);
        let [pc8_15] = trace_eval!(trace_eval, Column::PcNext8_15);
        let [pc_high] = trace_eval!(trace_eval, Column::PcHigh);

        let pc_low = pc_aux.clone() * BaseField::from(4) + pc8_15.clone() * BaseField::from(1 << 8);

        // Logup Interactions
        let (rel_cont_prog_exec, range_check) = lookup_elements;

        range_check.range64.constrain(eval, is_pad.clone(), pc_aux);
        range_check.range256.constrain(eval, is_pad.clone(), pc8_15);

        // Lookup 16 bits
        let [clk_low, clk_high] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);

        // consume(rel-cont-prog-exec, 1 − is-pad, (clk, pc))
        eval.add_to_relation(RelationEntry::new(
            rel_cont_prog_exec,
            (is_pad.clone() - E::F::one()).into(),
            &[
                clk_low.clone(),
                clk_high.clone(),
                pc_low.clone(),
                pc_high.clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    use crate::{
        components::{
            CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary, ADD, ADDI, RANGE16, RANGE256, RANGE64, RANGE8,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };

    #[test]
    fn assert_cpu_constraints() {
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
        let mut claimed_sum = assert_component(Cpu, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &ADD,
                &ADDI,
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
