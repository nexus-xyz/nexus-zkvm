use std::marker::PhantomData;

use num_traits::One;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column,
    program::{ProgramStep, Word},
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::{ExecutionComponent, ExecutionLookupEval},
            decoding::{type_b, InstructionDecoding},
        },
        utils::{
            add_16bit_with_carry, add_with_carries, constraints::ClkIncrement,
            subtract_with_borrow, u32_to_16bit_parts_le,
        },
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
        RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod bgeu;
mod bltu;
mod columns;

use columns::{Column, PreprocessedColumn};

pub const BLTU: BranchCmpUnsigned<bltu::Bltu> = BranchCmpUnsigned::new();
pub const BGEU: BranchCmpUnsigned<bgeu::Bgeu> = BranchCmpUnsigned::new();

pub trait BranchOp:
    InstructionDecoding<
    PreprocessedColumn = PreprocessedColumn,
    MainColumn = Column,
    DecodingColumn = type_b::DecodingColumn,
>
{
    /// Returns the flag used for enforcing the branch operation, pc is set to pc + imm when the flag is true,
    /// and to pc + 4 otherwise.
    fn enforce_branch_flag_eval<E: EvalAtRow>(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> E::F;
}

pub struct BranchCmpUnsigned<T> {
    _phantom: PhantomData<T>,
}

impl<T: BranchOp> ExecutionComponent for BranchCmpUnsigned<T> {
    const OPCODE: BuiltinOpcode = <T as InstructionDecoding>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = false;
}

struct ExecutionResult {
    diff_bytes: Word,
    borrow_bits: [bool; 2], // At 16-bit boundaries
    carry_bits: [bool; 2],  // At 16-bit boundaries
}

impl<T: BranchOp> BranchCmpUnsigned<T> {
    const fn new() -> Self {
        assert!(matches!(
            T::OPCODE,
            BuiltinOpcode::BGEU | BuiltinOpcode::BLTU
        ));
        Self {
            _phantom: PhantomData,
        }
    }

    fn execute_step(program_step: ProgramStep) -> ExecutionResult {
        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        let (diff_bytes, borrow_bits) = subtract_with_borrow(value_a, value_b);

        let (_, carry_bits) = match (T::OPCODE, borrow_bits[3]) {
            (BuiltinOpcode::BGEU, false) | (BuiltinOpcode::BLTU, true) => add_with_carries(pc, imm),
            (BuiltinOpcode::BGEU, true) | (BuiltinOpcode::BLTU, false) => {
                add_with_carries(pc, 4u32.to_le_bytes())
            }
            _ => panic!("invalid opcode"),
        };

        let borrow_bits = [borrow_bits[1], borrow_bits[3]];
        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            diff_bytes,
            borrow_bits,
            carry_bits,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let step = &program_step.step;

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let pc_next = u32_to_16bit_parts_le(step.next_pc);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (_clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let ExecutionResult {
            diff_bytes,
            borrow_bits,
            carry_bits,
        } = Self::execute_step(program_step);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, program_step.get_value_a(), Column::AVal);
        trace.fill_columns(row_idx, program_step.get_value_b(), Column::BVal);

        trace.fill_columns(row_idx, diff_bytes, Column::HRem);
        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);

        range_check_accum.range256.add_values(&diff_bytes);
    }
}

impl<T: BranchOp> BuiltInComponent for BranchCmpUnsigned<T> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
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
        let num_steps = <Self as ExecutionComponent>::iter_program_steps(side_note).count();
        let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut local_trace = TraceBuilder::new(log_size);
        let mut range_check_accum = RangeCheckAccumulator::default();

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(
                &mut common_trace,
                row_idx,
                program_step,
                &mut range_check_accum,
            );
            T::generate_trace_row(
                row_idx,
                &mut local_trace,
                program_step,
                &mut range_check_accum,
            );
        }
        side_note.range_check.append(range_check_accum);
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
            if T::OPCODE == BuiltinOpcode::BLTU {
                // (1 - h-neq-flag) * 4 term in pc-next constraint is non-zero on padding
                common_trace.fill_columns(row_idx, [4u16, 0], Column::PcNext);
            }
        }

        common_trace.finalize().concat(local_trace.finalize())
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
            Column::COLUMNS_NUM + T::DecodingColumn::COLUMNS_NUM
        );
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let h_rem = original_base_column!(component_trace, Column::HRem);
        range_check.range256.generate_logup_col(
            &mut logup_trace_builder,
            is_local_pad.clone(),
            &h_rem,
        );

        <T as InstructionDecoding>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            &range_check,
        );
        <Self as ExecutionComponent>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            side_note,
            &(
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            is_local_pad,
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            lookup_elements;

        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = ClkIncrement {
            clk: Column::Clk,
            clk_carry: Column::ClkCarry,
        }
        .eval(eval, &trace_eval);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);

        let h_rem = trace_eval!(trace_eval, Column::HRem);

        let [h_borrow_1, h_borrow_2] = trace_eval!(trace_eval, Column::HBorrow);

        // constrain two bytes at a time
        //
        // (1 − is-local-pad) · (a-val(1) + h-borrow(1) · 2^8 − b-val(1) − h-rem(1) ) = 0
        // (1 − is-local-pad) · (a-val(2) + h-borrow(2) · 2^8 − b-val(2) − h-rem(2) − h-borrow(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[0].clone() + a_val[1].clone() * BaseField::from(1 << 8)
                    - b_val[0].clone()
                    - b_val[1].clone() * BaseField::from(1 << 8)
                    - h_rem[0].clone()
                    - h_rem[1].clone() * BaseField::from(1 << 8)
                    + h_borrow_1.clone() * BaseField::from(1 << 8).pow(2)),
        );
        // (1 − is-local-pad) · (a-val(3) + h-borrow(3) · 2^8 − b-val(3) − h-rem(3) − h-borrow(2)) = 0
        // (1 − is-local-pad) · (a-val(4) + h-borrow(4) · 2^8 − b-val(4) − h-rem(4) − h-borrow(3)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[2].clone() + a_val[3].clone() * BaseField::from(1 << 8)
                    - b_val[2].clone()
                    - b_val[3].clone() * BaseField::from(1 << 8)
                    - h_rem[2].clone()
                    - h_rem[3].clone() * BaseField::from(1 << 8)
                    + h_borrow_2.clone() * BaseField::from(1 << 8).pow(2)
                    - h_borrow_1.clone()),
        );

        // (h-borrow(1)) · (1 − h-borrow(1) ) = 0
        // (h-borrow(2)) · (1 − h-borrow(2) ) = 0
        eval.add_constraint(h_borrow_1.clone() * (E::F::one() - h_borrow_1));
        eval.add_constraint(h_borrow_2.clone() * (E::F::one() - h_borrow_2.clone()));

        let decoding_trace_eval =
            TraceEval::<EmptyPreprocessedColumn, T::DecodingColumn, E>::new(eval);
        let enforce_branch_flag = T::enforce_branch_flag_eval(&trace_eval);

        let c_val = type_b::CVal.eval(&decoding_trace_eval);
        let [h_carry_1, h_carry_2] = trace_eval!(trace_eval, Column::HCarry);
        // (1 − is-local-pad) · (enforce-flag · c-val(1) + (1 - enforce-flag) · 4 + pc(1) − pc-next(1) − h-carry(1) · 2^8) = 0
        // (1 − is-local-pad) · (enforce-flag · c-val(2) + pc(2) + h-carry(1) − pc-next(2) − h-carry(2) · 2^8 ) = 0
        // (1 − is-local-pad) · (enforce-flag · c-val(3) + pc(3) + h-carry(2) − pc-next(3) − h-carry(3) · 2^8 ) = 0
        // (1 − is-local-pad) · (enforce-flag · c-val(4) + pc(4) + h-carry(3) − pc-next(4) − h-carry(4) · 2^8 ) = 0
        eval.add_constraint(
            enforce_branch_flag.clone()
                * (c_val[0].clone() + c_val[1].clone() * BaseField::from(1 << 8))
                + (E::F::one() - enforce_branch_flag.clone()) * E::F::from(4u32.into())
                + pc[0].clone()
                - h_carry_1.clone() * BaseField::from(1 << 8).pow(2)
                - pc_next[0].clone(),
        );
        eval.add_constraint(
            enforce_branch_flag.clone()
                * (c_val[2].clone() + c_val[3].clone() * BaseField::from(1 << 8))
                + pc[1].clone()
                + h_carry_1.clone()
                - h_carry_2.clone() * BaseField::from(1 << 8).pow(2)
                - pc_next[1].clone(),
        );
        // (h-carry(1)) · (1 − h-carry(1) ) = 0
        // (h-carry(2)) · (1 − h-carry(2) ) = 0
        eval.add_constraint(h_carry_1.clone() * (E::F::one() - h_carry_1));
        eval.add_constraint(h_carry_2.clone() * (E::F::one() - h_carry_2));

        range_check
            .range256
            .constrain(eval, is_local_pad.clone(), &h_rem);

        T::constrain_decoding(eval, &trace_eval, &decoding_trace_eval, range_check);

        // Logup Interactions
        let reg_addrs = T::combine_reg_addresses(&decoding_trace_eval);
        let instr_val = T::combine_instr_val(&decoding_trace_eval);

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            ExecutionLookupEval {
                is_local_pad,
                reg_addrs,
                reg_values: [a_val, b_val, zero_array::<WORD_SIZE, E>()],
                instr_val,
                clk,
                clk_next,
                pc,
                pc_next,
            },
        );

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::execution::branch_cmp_signed::tests::assert_branch_cmp_constraints;

    use nexus_vm::riscv::{BuiltinOpcode, Instruction, Opcode};

    #[test]
    fn assert_bltu_constraints() {
        let instructions = &[
            // Set x10 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 0, 1),
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Set x5 = 0xFFFFFFFF (max unsigned value)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 10),
            // Case 1: BLTU with equal values (should not branch)
            // BLTU x1, x3, 0xff (should not branch as x1 < x3 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 1, 3, 0xff),
            // Case 2: BLTU with different values (should branch)
            // BLTU x1, x2, 12 (branch to PC + 12 as x1 < x2 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 1, 2, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BLTU with zero and non-zero (should branch)
            // BLTU x0, x1, 8 (branch to PC + 8 as x0 < x1 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 0, 1, 8),
            // No-op instruction to fill the gap (should not be executed)
            Instruction::unimpl(),
            // Case 4: BLTU with zero and zero (should not branch)
            // BLTU x0, x0, 8 (should not branch as x0 < x0 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 0, 0, 0xff),
            // Case 5: BLTU with negative and positive values (should not branch)
            // BLTU x4, x1, 8 (should not branch as 0xfffffff6 > 10 unsigned)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 4, 1, 0xff),
            // Case 6: BLTU with max unsigned value and zero (should not branch)
            // BLTU x5, x0, 8 (should not branch as 0xFFFFFFFF > 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 5, 0, 0xff),
            // Case 7: BLTU with zero and max unsigned value (should branch)
            // BLTU x0, x5, 12 (branch to PC + 12 as 0 < 0xFFFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 0, 5, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
        ];

        assert_branch_cmp_constraints(BLTU, instructions);
    }

    #[test]
    fn assert_bgeu_constraints() {
        let instructions = &[
            // Set x10 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 0, 1),
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Set x5 = 0xFFFFFFFF (max unsigned value)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 10),
            // Case 1: BGEU with equal values (should branch)
            // BGEU x1, x3, 0xff (should branch as x1 >= x3 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 1, 3, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 2: BGEU with different values (should not branch)
            // BGEU x1, x2, 12 (should not branch as x1 >= x2 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 1, 2, 0xff),
            // Case 3: BGEU with zero and non-zero (should not branch)
            // BGEU x0, x1, 8 (should not branch as x0 >= x1 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 0, 1, 0xff),
            // Case 4: BGEU with zero and zero (should branch)
            // BGEU x0, x0, 0xff (should branch as x0 >= x0 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 0, 0, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 5: BGEU with negative and positive values (should branch)
            // BGEU x4, x1, 0xff (should branch as 0xfffffff6 >= 10 unsigned)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 4, 1, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 6: BGEU with max unsigned value and zero (should branch)
            // BGEU x5, x0, 0xff (should branch as 0xFFFFFFFF >= 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 5, 0, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 7: BGEU with zero and max unsigned value (should not branch)
            // BGEU x0, x5, 12 (should not branch as 0 >= 0xFFFFFFFF is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGEU), 0, 5, 0xff),
        ];

        assert_branch_cmp_constraints(BGEU, instructions);
    }
}
