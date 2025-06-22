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
    preprocessed_base_column, preprocessed_trace_eval, trace_eval, virtual_column::VirtualColumn,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, CpuToInstLookupElements,
        CpuToProgMemoryLookupElements, CpuToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements,
    },
    side_note::SideNote,
};

mod columns;
mod trace;

pub use self::{columns::HalfWord, trace::preprocessed_clk_trace};
use columns::{Column, PreprocessedColumn, IS_ALU, PC_HIGH, PC_LOW};

pub struct Cpu;

impl BuiltInComponent for Cpu {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        CpuToInstLookupElements,
        ProgramExecutionLookupElements,
        CpuToRegisterMemoryLookupElements,
        CpuToProgMemoryLookupElements,
    );

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let cols = preprocessed_clk_trace(log_size);
        FinalizedTrace { cols, log_size }
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
        let (rel_cpu_to_inst, rel_cont_prog_exec, rel_cpu_to_reg_memory, rel_cpu_to_prog_memory) =
            Self::LookupElements::get(lookup_elements);
        let log_size = component_trace.log_size();
        let mut logup_trace_builder = LogupTraceBuilder::new(log_size);

        let [is_pad] = original_base_column!(component_trace, Column::IsPad);

        let a_val = original_base_column!(component_trace, Column::AVal);
        let b_val = original_base_column!(component_trace, Column::BVal);
        let c_val = original_base_column!(component_trace, Column::CVal);

        let [op_a] = original_base_column!(component_trace, Column::OpA);
        let [op_b] = original_base_column!(component_trace, Column::OpB);
        let [op_c] = original_base_column!(component_trace, Column::OpC);

        let [opcode] = original_base_column!(component_trace, Column::Opcode);

        let [clk_low, clk_high] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::Clk);
        let pc_low = PC_LOW.combine_from_finalized_trace(&component_trace);
        let pc_high = PC_HIGH.combine_from_finalized_trace(&component_trace);

        let pc = original_base_column!(component_trace, Column::Pc);
        let instr_val = original_base_column!(component_trace, Column::InstrVal);

        // consume(rel-cont-prog-exec, 1 − is-pad, (clk, pc))
        logup_trace_builder.add_to_relation_with(
            &rel_cont_prog_exec,
            [is_pad.clone()],
            |[is_pad]| (is_pad - PackedBaseField::one()).into(),
            &[
                clk_low.clone(),
                clk_high.clone(),
                pc_low.clone(),
                pc_high.clone(),
            ],
        );

        // consume(rel-cpu-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        logup_trace_builder.add_to_relation_with(
            &rel_cpu_to_prog_memory,
            [is_pad.clone()],
            |[is_pad]| (is_pad - PackedBaseField::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        );

        let is_alu = IS_ALU.combine_from_finalized_trace(&component_trace);

        // TODO: for logup trace generation the prover can use side-note to compute the numerator.
        //
        // provide(
        //     rel-cpu-to-inst,
        //     is-type-u + is-type-j + is-load + is-type-s + is-type-b + is-alu,
        //     (clk, opcode, pc, a-val, b-val, c-val)
        // )
        logup_trace_builder.add_to_relation(
            &rel_cpu_to_inst,
            is_alu,
            &[
                [clk_low.clone(), clk_high.clone(), opcode, pc_low, pc_high].as_slice(),
                &a_val,
                &b_val,
                &c_val,
            ]
            .concat(),
        );

        // provide(rel-cpu-to-reg-memory, 1 − is-pad, (clk, op-a, op-b, op-c))
        logup_trace_builder.add_to_relation_with(
            &rel_cpu_to_reg_memory,
            [is_pad],
            |[is_pad]| (PackedBaseField::one() - is_pad).into(),
            &[clk_low, clk_high, op_a, op_b, op_c],
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

        let pc = trace_eval!(trace_eval, Column::Pc);
        let [pc_aux] = trace_eval!(trace_eval, Column::PcAux);
        let instr_val = trace_eval!(trace_eval, Column::InstrVal);

        eval.add_constraint(pc_aux * BaseField::from(4) - pc[0].clone());

        let [opcode] = trace_eval!(trace_eval, Column::Opcode);
        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = trace_eval!(trace_eval, Column::CVal);

        let [op_a] = trace_eval!(trace_eval, Column::OpA);
        let [op_b] = trace_eval!(trace_eval, Column::OpB);
        let [op_c] = trace_eval!(trace_eval, Column::OpC);

        // Logup Interactions
        let (rel_cpu_to_inst, rel_cont_prog_exec, rel_cpu_to_reg_memory, rel_cpu_to_prog_memory) =
            lookup_elements;

        // Lookup 16 bits
        let [clk_low, clk_high] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);
        let pc_low = PC_LOW.eval(&trace_eval);
        let pc_high = PC_HIGH.eval(&trace_eval);

        let is_alu = IS_ALU.eval(&trace_eval);

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

        // consume(rel-cpu-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        eval.add_to_relation(RelationEntry::new(
            rel_cpu_to_prog_memory,
            (is_pad.clone() - E::F::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        ));

        // provide(
        //     rel-cpu-to-inst,
        //     is-type-u + is-type-j + is-load + is-type-s + is-type-b + is-alu,
        //     (clk, opcode, pc, a-val, b-val, c-val)
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_cpu_to_inst,
            is_alu.into(),
            &[
                [
                    clk_low.clone(),
                    clk_high.clone(),
                    opcode.clone(),
                    pc_low.clone(),
                    pc_high.clone(),
                ]
                .as_slice(),
                &a_val,
                &b_val,
                &c_val,
            ]
            .concat(),
        ));

        // provide(rel-cpu-to-reg-memory, 1 − is-pad, (clk, op-a, op-b, op-c))
        eval.add_to_relation(RelationEntry::new(
            rel_cpu_to_reg_memory,
            (E::F::one() - is_pad).into(),
            &[clk_low, clk_high, op_a, op_b, op_c],
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
            RegisterMemoryBoundary, ADD, ADDI,
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
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
