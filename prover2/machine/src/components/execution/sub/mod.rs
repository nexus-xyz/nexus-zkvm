use num_traits::One;
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
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    program::{ProgramStep, Word},
    trace_eval,
};

use crate::{
    components::{
        execution::{common::ExecutionComponent, decoding::type_r},
        utils::{
            add_16bit_with_carry,
            constraints::{ClkIncrement, PcIncrement},
            subtract_with_borrow, u32_to_16bit_parts_le,
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
use columns::{Column, PreprocessedColumn};

pub const SUB: Sub = Sub;

pub struct Sub;

impl ExecutionComponent for Sub {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SUB;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = true;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;

    type Column = Column;
}

struct ExecutionResult {
    pub borrow_bits: [bool; 2], // for 16-bit boundaries
    pub diff_bytes: Word,
}

impl Sub {
    fn execute_step(value_b: Word, value_c: Word) -> ExecutionResult {
        let (diff_bytes, borrow_bits) = subtract_with_borrow(value_b, value_c);
        let borrow_bits = [borrow_bits[1], borrow_bits[3]];

        ExecutionResult {
            borrow_bits,
            diff_bytes,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let ExecutionResult {
            borrow_bits,
            diff_bytes,
        } = Self::execute_step(value_b, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &value_c, Column::CVal);
        trace.fill_columns_bytes(row_idx, &diff_bytes, Column::AVal);
        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);
    }
}

impl BuiltInComponent for Sub {
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
        let mut decoding_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
            type_r::generate_trace_row(row_idx, &mut decoding_trace, program_step);
        }
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize().concat(decoding_trace.finalize())
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
        assert_eq!(
            component_trace.original_trace.len(),
            Column::COLUMNS_NUM + type_r::DecodingColumn::COLUMNS_NUM
        );
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
        let [h_borrow_1, h_borrow_2] = trace_eval!(trace_eval, Column::HBorrow);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = trace_eval!(trace_eval, Column::CVal);

        ClkIncrement {
            is_local_pad: Column::IsLocalPad,
            clk: Column::Clk,
            clk_next: Column::ClkNext,
            clk_carry: Column::ClkCarry,
        }
        .constrain(eval, &trace_eval);
        PcIncrement {
            is_local_pad: Column::IsLocalPad,
            pc: Column::Pc,
            pc_next: Column::PcNext,
            pc_carry: Column::PcCarry,
        }
        .constrain(eval, &trace_eval);

        let modulus = E::F::from(256u32.into());

        // subtracting 2 limbs at a time
        //
        // (1 − is-local-pad) · (
        //     a-val(1) + a-val(2) · 2^8
        //     − h-borrow(1) · 2^16
        //     − (b-val(1) + b-val(2) · 2^8 − c-val(1) − c-val(2) · 2^8)
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[0].clone() + a_val[1].clone() * modulus.clone()
                    - h_borrow_1.clone() * modulus.clone().pow(2)
                    - (b_val[0].clone() + b_val[1].clone() * modulus.clone()
                        - c_val[0].clone()
                        - c_val[1].clone() * modulus.clone())),
        );
        // (1 − is-local-pad) · (
        //     a-val(3) + a-val(4) · 2^8
        //     − h-borrow(2) · 2^16
        //     − (b-val(3) + b-val(4) · 2^8 − c-val(3) − c-val(4) · 2^8 − h-borrow(1))
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[2].clone() + a_val[3].clone() * modulus.clone()
                    - h_borrow_2.clone() * modulus.clone().pow(2)
                    - (b_val[2].clone() + b_val[3].clone() * modulus.clone()
                        - c_val[2].clone()
                        - c_val[3].clone() * modulus.clone()
                        - h_borrow_1.clone())),
        );

        let decoding_trace_eval =
            TraceEval::<EmptyPreprocessedColumn, type_r::DecodingColumn, E>::new(eval);

        // Logup Interactions
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;

        let instr_val = type_r::InstrVal::new(
            Self::OPCODE.raw(),
            Self::OPCODE.fn3().value(),
            Self::OPCODE.fn7().value(),
        )
        .eval(&decoding_trace_eval);
        let op_a = type_r::OP_A.eval(&decoding_trace_eval);
        let op_b = type_r::OP_B.eval(&decoding_trace_eval);
        let op_c = type_r::OP_C.eval(&decoding_trace_eval);

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            &trace_eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            [op_a, op_b, op_c],
            [a_val, b_val, c_val],
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
            RegisterMemoryBoundary, ADDI,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_sub_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 127),
            // x2 = x1 - x0 => 127 - 0 = 127
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 2, 1, 0),
            // x3 = x2 - x1 => 127 - 127 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 3, 2, 1),
            // x4 = x3 - x2 => 0 - 127 = -127 (as unsigned = 0xFFFFFF81)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 3, 2),
            // x5 = x4 - x3 => (-127) - 0 = -127
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 4, 3),
            // x6 = x5 - x4 => (-127) - (-127) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 6, 5, 4),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 1, 1230), // x2 = x1 + 1230
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 3, 2, 1),     // x3 = x2 - x1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 3, 1231), // x4 = x3 + 1231
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 4, 3),     // x5 = x4 - x3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 5, 1232), // x6 = x5 + 1232
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(Sub, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &ADDI,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
