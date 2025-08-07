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
        RangeCheckLookupElements, RangeLookupBound,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod bge;
mod blt;
mod columns;

use columns::{Column, PreprocessedColumn};

pub const BLT: BranchCmpSigned<blt::Blt> = BranchCmpSigned::new();
pub const BGE: BranchCmpSigned<bge::Bge> = BranchCmpSigned::new();

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

pub struct BranchCmpSigned<T> {
    _phantom: PhantomData<T>,
}

impl<T: BranchOp> ExecutionComponent for BranchCmpSigned<T> {
    const OPCODE: BuiltinOpcode = <T as InstructionDecoding>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = false;
}

struct ExecutionResult {
    diff_bytes: Word,
    borrow_bits: [bool; 2], // at 16-bit boundaries
    carry_bits: [bool; 2],
    lt_flag: bool,
    h2: Word,
    h3: Word,
}

impl<T: BranchOp> BranchCmpSigned<T> {
    const fn new() -> Self {
        assert!(matches!(T::OPCODE, BuiltinOpcode::BGE | BuiltinOpcode::BLT));
        Self {
            _phantom: PhantomData,
        }
    }

    fn execute_step(program_step: ProgramStep) -> ExecutionResult {
        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let sgn_a = program_step.get_sgn_a();
        let sgn_b = program_step.get_sgn_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        let (diff_bytes, borrow_bits) = subtract_with_borrow(value_a, value_b);

        let result = match (sgn_a, sgn_b) {
            (false, false) | (true, true) => borrow_bits[3],
            (false, true) => false,
            (true, false) => true,
        };

        let borrow_bits = [borrow_bits[1], borrow_bits[3]];

        // lt_flag is equal to result
        let (_, carry_bits) = match (T::OPCODE, result) {
            (BuiltinOpcode::BGE, true) | (BuiltinOpcode::BLT, false) => {
                add_with_carries(pc, 4u32.to_le_bytes())
            }
            (BuiltinOpcode::BGE, false) | (BuiltinOpcode::BLT, true) => add_with_carries(pc, imm),
            _ => panic!("invalid opcode"),
        };

        let mut h2 = value_a;
        let mut h3 = value_b;
        // h2 and h3 are value_a and value_b with the sign bit cleared
        h2[WORD_SIZE - 1] &= 0x7f;
        h3[WORD_SIZE - 1] &= 0x7f;

        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            diff_bytes,
            borrow_bits,
            carry_bits,
            lt_flag: result,
            h2,
            h3,
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
            lt_flag,
            h2,
            h3,
        } = Self::execute_step(program_step);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, program_step.get_value_a(), Column::AVal);
        trace.fill_columns(row_idx, program_step.get_value_b(), Column::BVal);

        let h_rem_a = h2[WORD_SIZE - 1];
        let h_rem_b = h3[WORD_SIZE - 1];
        trace.fill_columns(row_idx, diff_bytes, Column::HRem);
        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);

        let h_sgn_a = program_step.get_sgn_a();
        let h_sgn_b = program_step.get_sgn_b();
        trace.fill_columns(row_idx, h_sgn_a, Column::HSgnA);
        trace.fill_columns(row_idx, h_sgn_b, Column::HSgnB);
        trace.fill_columns(row_idx, h_sgn_a == h_sgn_b, Column::HSgnEq);

        trace.fill_columns(row_idx, h_rem_a, Column::HRemA);
        trace.fill_columns(row_idx, h_rem_b, Column::HRemB);
        trace.fill_columns(row_idx, lt_flag, Column::HLtFlag);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);

        range_check_accum.range256.add_values(&diff_bytes);
        range_check_accum
            .range128
            .add_values_from_slice(&[h_rem_a, h_rem_b]);
    }
}

impl<T: BranchOp> BuiltInComponent for BranchCmpSigned<T> {
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
            if T::OPCODE == BuiltinOpcode::BLT {
                // (1 - h-neq-flag) * 4 term in pc-next constraint is non-zero on padding
                common_trace.fill_columns(row_idx, [4u16, 0], Column::PcNext);
            }
            // h-sgn-eq = (h-sgn-a)(h-sgn-b) + (1 − h-sgn-a)(1 − h-sgn-b) is non-zero on padding
            common_trace.fill_columns(row_idx, true, Column::HSgnEq);
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
        let [h_rem_a] = original_base_column!(component_trace, Column::HRemA);
        let [h_rem_b] = original_base_column!(component_trace, Column::HRemB);
        // range checks
        range_check.range256.generate_logup_col(
            &mut logup_trace_builder,
            is_local_pad.clone(),
            &h_rem,
        );
        for rem in [h_rem_a, h_rem_b] {
            range_check.range128.generate_logup_col(
                &mut logup_trace_builder,
                is_local_pad.clone(),
                rem,
            );
        }

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
        let [h_rem_a] = trace_eval!(trace_eval, Column::HRemA);
        let [h_rem_b] = trace_eval!(trace_eval, Column::HRemB);

        let [h_sgn_a] = trace_eval!(trace_eval, Column::HSgnA);
        let [h_sgn_b] = trace_eval!(trace_eval, Column::HSgnB);

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

        // (1 − is-local-pad) · (h-rem-a + h-sgn-a · 2^7 − a-val(4) ) = 0
        // (1 − is-local-pad) · (h-rem-b + h-sgn-b · 2^7 − b-val(4) ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem_a.clone() + h_sgn_a.clone() * BaseField::from(1 << 7)
                    - a_val[WORD_SIZE - 1].clone()),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem_b.clone() + h_sgn_b.clone() * BaseField::from(1 << 7)
                    - b_val[WORD_SIZE - 1].clone()),
        );

        let h_ltu_flag = h_borrow_2;
        let [h_lt_flag] = trace_eval!(trace_eval, Column::HLtFlag);
        let [h_sgn_eq] = trace_eval!(trace_eval, Column::HSgnEq);

        // (h-sgn-a) · (1 − h-sgn-a) = 0
        // (h-sgn-b) · (1 − h-sgn-b) = 0
        eval.add_constraint(h_sgn_a.clone() * (E::F::one() - h_sgn_a.clone()));
        eval.add_constraint(h_sgn_b.clone() * (E::F::one() - h_sgn_b.clone()));

        // To enforce this constrain with lower degree, extract the expression h-sgn-eq = (h-sgn-a)(h-sgn-b) + (1 − h-sgn-a)(1 − h-sgn-b)
        //
        // (1 − is-local-pad) · ((h-sgn-a)(1 − h-sgn-b) + h-ltu-flag((h-sgn-a)(h-sgn-b) + (1 − h-sgn-a)(1 − h-sgn-b)) − h-lt-flag) = 0
        eval.add_constraint(
            h_sgn_a.clone() * h_sgn_b.clone()
                + (E::F::one() - h_sgn_a.clone()) * (E::F::one() - h_sgn_b.clone())
                - h_sgn_eq.clone(),
        );
        eval.add_constraint(
            h_sgn_a.clone() * (E::F::one() - h_sgn_b.clone()) + h_ltu_flag.clone() * h_sgn_eq
                - h_lt_flag.clone(),
        );

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

        // range checks
        range_check
            .range256
            .constrain(eval, is_local_pad.clone(), &h_rem);
        for rem in [h_rem_a, h_rem_b] {
            range_check
                .range128
                .constrain(eval, is_local_pad.clone(), rem);
        }

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
pub mod tests {
    use super::*;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary, ADDI, RANGE128, RANGE16, RANGE256, RANGE64, RANGE8, SUB,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    pub fn assert_branch_cmp_constraints<C>(component: C, instructions: &[Instruction])
    where
        C: BuiltInComponent + 'static + Sync,
        C::LookupElements: 'static + Sync,
    {
        let basic_block = vec![BasicBlock::new(instructions.to_owned())];

        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(component, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &SUB,
                &ADDI,
                &RANGE8,
                &RANGE16,
                &RANGE64,
                &RANGE128,
                &RANGE256,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }

    #[test]
    fn assert_blt_constraints() {
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
            // Set x5 = -1 (0xFFFFFFFF as signed)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 10),
            // Case 1: BLT with equal values (should not branch)
            // BLT x1, x3, 0xff (should not branch as x1 < x3 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 1, 3, 0xff),
            // Case 2: BLT with different values (should branch)
            // BLT x1, x2, 12 (branch to PC + 12 as x1 < x2 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 1, 2, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BLT with zero and positive (should branch)
            // BLT x0, x1, 8 (branch to PC + 8 as x0 < x1 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 0, 1, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            // Case 4: BLT with zero and zero (should not branch)
            // BLT x0, x0, 8 (should not branch as x0 < x0 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 0, 0, 0xff),
            // Case 5: BLT with negative and positive values (should branch)
            // BLT x4, x1, 8 (should branch as -10 < 10)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 4, 1, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 6: BLT with -1 and zero (should branch)
            // BLT x5, x0, 8 (should branch as -1 < 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 5, 0, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 7: BLT with zero and -1 (should not branch)
            // BLT x0, x5, 12 (should not branch as 0 > -1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 0, 5, 0xff),
        ];

        assert_branch_cmp_constraints(BLT, instructions);
    }

    #[test]
    fn assert_bge_constraints() {
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
            // Set x5 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 10),
            // Set x6 = 1000 (a large positive number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 0, 1000),
            // Set x7 = -1000 (a large negative number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 7, 0, 6),
            // Case 1: BGE with equal values (should branch)
            // BGE x1, x3, 12 (should branch as x1 >= x3 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 1, 3, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 2: BGE with different values (should not branch)
            // BGE x1, x2, 0xff (should not branch as x1 >= x2 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 1, 2, 0xff),
            // Case 3: BGE with zero and positive (should not branch)
            // BGE x0, x1, 0xff (should not branch as x0 >= x1 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 0, 1, 0xff),
            // Case 4: BGE with zero and zero (should branch)
            // BGE x0, x0, 12 (should branch as x0 >= x0 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 0, 0, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 5: BGE with negative and positive values (should not branch)
            // BGE x4, x1, 0xff (should not branch as -10 >= 10 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 4, 1, 0xff),
            // Case 6: BGE with negative and zero (should not branch)
            // BGE x5, x0, 0xff (should not branch as -1 >= 0 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 5, 0, 0xff),
            // Case 7: BGE with zero and negative value (should branch)
            // BGE x0, x5, 12 (should branch as 0 >= -1 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 0, 5, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 8: BGE with large positive and zero (should branch)
            // BGE x6, x0, 12 (should branch as 1000 >= 0 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 6, 0, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 9: BGE with large negative and zero (should not branch)
            // BGE x7, x0, 0xff (should not branch as -1000 >= 0 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 7, 0, 0xff),
            // Case 10: BGE with large positive and large negative (should branch)
            // BGE x6, x7, 12 (should branch as 1000 >= -1000 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BGE), 6, 7, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
        ];

        assert_branch_cmp_constraints(BGE, instructions);
    }
}
