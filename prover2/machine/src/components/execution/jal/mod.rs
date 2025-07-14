use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    program::{ProgramStep, Word},
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::common::ExecutionComponent,
        utils::{
            add_16bit_with_carry, add_with_carries, constraints::ClkIncrement,
            u32_to_16bit_parts_le,
        },
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
mod decoding;

use columns::{CVal, Column, InstrVal, PreprocessedColumn, OP_A};

pub const JAL: Jal = Jal;

pub struct Jal;

impl ExecutionComponent for Jal {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::JAL;

    const REG1_ACCESSED: bool = false;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;

    type Column = Column;
}

struct ExecutionResult {
    pc_carry_bits: [bool; 2], // At 16-bit boundaries
    a_val: Word,
    carry_bits: [bool; 2], // At 16-bit boundaries
}

impl Jal {
    fn execute_step(program_step: ProgramStep) -> ExecutionResult {
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        // 1. Compute pc_next = pc + imm
        // 2. value_a = pc + 4
        let (_, pc_carry_bits) = add_with_carries(pc, imm);
        let (value_a, carry_bits) = add_with_carries(pc, 4u32.to_le_bytes());

        let pc_carry_bits = [pc_carry_bits[1], pc_carry_bits[3]];
        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            pc_carry_bits,
            a_val: value_a,
            carry_bits,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;
        assert_eq!(step.instruction.opcode.builtin(), Some(Self::OPCODE));

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let pc_next = u32_to_16bit_parts_le(step.next_pc);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let ExecutionResult {
            pc_carry_bits,
            a_val,
            carry_bits,
        } = Self::execute_step(program_step);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry_bits, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);

        self.generate_decoding_trace_row(trace, row_idx, program_step);
    }
}

impl BuiltInComponent for Jal {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = <Self as ExecutionComponent>::iter_program_steps(side_note).count();
        let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
        }
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize()
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
        assert_eq!(component_trace.original_trace.len(), Column::COLUMNS_NUM);
        let lookup_elements = Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        <Self as ExecutionComponent>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            side_note,
            &lookup_elements,
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

        let a_val = trace_eval!(trace_eval, Column::AVal);

        ClkIncrement {
            is_local_pad: Column::IsLocalPad,
            clk: Column::Clk,
            clk_next: Column::ClkNext,
            clk_carry: Column::ClkCarry,
        }
        .constrain(eval, &trace_eval);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);

        let [h_carry_1, h_carry_2] = trace_eval!(trace_eval, Column::HCarry);
        // add two bytes at a time
        //
        // (1 − is-local-pad) · (pc(1) + 4 − a-val(1) − h-carry(1) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(2) + h-carry(1) − a-val(2) − h-carry(2) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (E::F::from(4.into()) + pc[0].clone()
                    - h_carry_1.clone() * BaseField::from(1 << 8).pow(2)
                    - a_val[0].clone()
                    - a_val[1].clone() * BaseField::from(1 << 8)),
        );
        // (1 − is-local-pad) · (pc(3) + h-carry(2) − a-val(3) − h-carry(3) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(4) + h-carry(3) − a-val(4) − h-carry(4) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc[1].clone() + h_carry_1.clone()
                    - h_carry_2.clone() * BaseField::from(1 << 8).pow(2)
                    - a_val[2].clone()
                    - a_val[3].clone() * BaseField::from(1 << 8)),
        );
        // (h-carry(1)) · (1 − h-carry(1) ) = 0
        // (h-carry(2)) · (1 − h-carry(2) ) = 0
        eval.add_constraint(h_carry_1.clone() * (E::F::one() - h_carry_1));
        eval.add_constraint(h_carry_2.clone() * (E::F::one() - h_carry_2));

        let c_val = CVal.eval(&trace_eval);
        let [pc_carry_1, pc_carry_2] = trace_eval!(trace_eval, Column::PcCarry);
        // add two bytes at a time
        //
        // (1 − is-local-pad) · (pc(1) + c-val(1) − pc-next(1) − pc-carry(1) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(2) + c-val(2) + pc-carry(1) − pc-next(2) − pc-carry(2) · 2^8) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (c_val[0].clone() + c_val[1].clone() * BaseField::from(1 << 8) + pc[0].clone()
                    - pc_carry_1.clone() * BaseField::from(1 << 8).pow(2)
                    - pc_next[0].clone()),
        );
        // (1 − is-local-pad) · (pc(3) + c-val(3) + pc-carry(2) − pc-next(3) − pc-carry(3) · 2^8) = 0
        // (1 − is-local-pad) · (pc(4) + c-val(4) + pc-carry(3) − pc-next(4) − pc-carry(4) · 2^8)
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (c_val[2].clone()
                    + c_val[3].clone() * BaseField::from(1 << 8)
                    + pc[1].clone()
                    + pc_carry_1.clone()
                    - pc_carry_2.clone() * BaseField::from(1 << 8).pow(2)
                    - pc_next[1].clone()),
        );
        // (pc-carry(1)) · (1 − pc-carry(1) ) = 0
        // (pc-carry(2)) · (1 − pc-carry(2) ) = 0
        eval.add_constraint(pc_carry_1.clone() * (E::F::one() - pc_carry_1));
        eval.add_constraint(pc_carry_2.clone() * (E::F::one() - pc_carry_2));

        Self::constrain_decoding(eval, &trace_eval);

        let op_a = OP_A.eval(&trace_eval);
        let op_b = E::F::zero();
        let op_c = E::F::zero();
        let instr_val = InstrVal.eval(&trace_eval);

        // Logup Interactions
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            &trace_eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            [op_a, op_b, op_c],
            [
                a_val,
                zero_array::<WORD_SIZE, E>(),
                zero_array::<WORD_SIZE, E>(),
            ],
            instr_val,
        );

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };

    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_jal_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // Case 1: JAL with positive offset
            // JAL x3, 12 (Jump forward 12 bytes (3 instructions) and store return address in x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JAL), 3, 0, 12),
            // Instructions to skip
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 2: JAL with x0 as destination (used for unconditional jumps without saving return address)
            // JAL x0, 8 (Jump forward 8 bytes (2 instructions) without saving return address)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JAL), 0, 0, 8),
            // Instruction to skip
            Instruction::unimpl(),
        ])];

        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(Jal, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
