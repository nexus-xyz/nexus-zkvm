//! Helper component needed to eliminate boundary logup terms in the cpu component.
//!
//! This can be done manually as a part of the protocol, but wrapped into component to keep interfaces
//! consistent.

use num_traits::One;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column, preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use super::utils::u32_to_16bit_parts_le;
use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements},
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct CpuBoundary;

impl CpuBoundary {
    const LOG_SIZE: u32 = LOG_N_LANES;
}

impl BuiltInComponent for CpuBoundary {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = ProgramExecutionLookupElements;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        assert_eq!(log_size, Self::LOG_SIZE);

        let mut trace = TraceBuilder::new(log_size);
        trace.fill_columns_base_field(0, &[BaseField::one()], PreprocessedColumn::Multiplicity);
        trace.fill_columns_base_field(1, &[-BaseField::one()], PreprocessedColumn::Multiplicity);

        trace.finalize()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let log_size = Self::LOG_SIZE;

        let first_step = side_note
            .iter_program_steps()
            .next()
            .expect("empty execution trace");
        let final_step = side_note
            .iter_program_steps()
            .next_back()
            .expect("empty execution trace");

        let init_pc = first_step.step.pc;

        let init_pc_parts = u32_to_16bit_parts_le(init_pc);
        let init_clk_parts = [1u16, 0];

        let final_pc = final_step.step.next_pc;
        let final_clk = final_step.step.timestamp + 1;

        let final_pc_parts = u32_to_16bit_parts_le(final_pc);
        let final_clk_parts = u32_to_16bit_parts_le(final_clk);

        let mut trace = TraceBuilder::new(log_size);

        trace.fill_columns(0, init_pc_parts, Column::Pc);
        trace.fill_columns(0, init_clk_parts, Column::Clk);

        trace.fill_columns(1, final_pc_parts, Column::Pc);
        trace.fill_columns(1, final_clk_parts, Column::Clk);

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
        let lookup_elements: &Self::LookupElements = lookup_elements.as_ref();

        let [mult] = preprocessed_base_column!(component_trace, PreprocessedColumn::Multiplicity);

        let clk = original_base_column!(component_trace, Column::Clk);
        let pc = original_base_column!(component_trace, Column::Pc);

        let mut logup_trace_builder = LogupTraceBuilder::new(Self::LOG_SIZE);

        logup_trace_builder.add_to_relation(lookup_elements, mult, &[clk, pc].concat());

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [mult] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Multiplicity);

        let clk = trace_eval!(trace_eval, Column::Clk);
        let pc = trace_eval!(trace_eval, Column::Pc);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            mult.into(),
            &[clk, pc].concat(),
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::framework::test_utils::{assert_component, AssertContext};
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    #[test]
    fn assert_cpu_boundary_constraints() {
        let basic_block = vec![BasicBlock::new(vec![Instruction::new_ir(
            Opcode::from(BuiltinOpcode::ADDI),
            2,
            1,
            0,
        )])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        assert_component(CpuBoundary, &mut AssertContext::new(&program_trace, &view));
    }
}
