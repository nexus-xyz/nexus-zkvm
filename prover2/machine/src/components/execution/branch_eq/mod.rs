use std::marker::PhantomData;

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
    program::ProgramStep,
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::ExecutionComponent,
            decoding::{type_b, InstructionDecoding},
        },
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

mod beq;
mod bne;
mod columns;

use columns::{Column, PreprocessedColumn};

pub const BEQ: BranchEq<beq::Beq> = BranchEq::new();
pub const BNE: BranchEq<bne::Bne> = BranchEq::new();

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

pub struct BranchEq<T> {
    _phantom: PhantomData<T>,
}

impl<T: BranchOp> ExecutionComponent for BranchEq<T> {
    const OPCODE: BuiltinOpcode = <T as InstructionDecoding>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = false;

    type Column = Column;
}

struct ExecutionResult {
    // Flag indicating if a_val != b_val
    neq_flag: bool,
    // Flag indicating if (a_val_1, a_val_2) != (b_val_1, b_val_2)
    neq_12_flag: bool,
    // Flag indicating if (a_val_3, a_val_4) != (b_val_3, b_val_4)
    neq_34_flag: bool,
    // Carry bits for addition at 16-bit boundaries
    carry_bits: [bool; 2],
    // Difference between a_val and b_val
    neq_aux: [BaseField; 2],
    // Inverse of the difference
    neq_aux_inv: [BaseField; 2],
}

impl<T: BranchOp> BranchEq<T> {
    const fn new() -> Self {
        assert!(matches!(T::OPCODE, BuiltinOpcode::BEQ | BuiltinOpcode::BNE));
        Self {
            _phantom: PhantomData,
        }
    }

    fn execute_step(program_step: ProgramStep) -> ExecutionResult {
        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();
        let pc_l = u16::from_be_bytes([pc[0], pc[1]]) as u32;
        let pc_h = u16::from_be_bytes([pc[2], pc[3]]) as u32;
        let value_a_l = u16::from_le_bytes([value_a[0], value_a[1]]) as u32;
        let value_b_l = u16::from_le_bytes([value_b[0], value_b[1]]) as u32;
        let value_a_h = u16::from_le_bytes([value_a[2], value_a[3]]) as u32;
        let value_b_h = u16::from_le_bytes([value_b[2], value_b[3]]) as u32;

        let (_, carry_bits) = match (T::OPCODE, value_a == value_b) {
            (BuiltinOpcode::BEQ, true) | (BuiltinOpcode::BNE, false) => add_with_carries(pc, imm),
            (BuiltinOpcode::BEQ, false) | (BuiltinOpcode::BNE, true) => {
                add_with_carries(pc, 4u32.to_le_bytes())
            }
            _ => panic!("invalid opcode"),
        };

        let neq_flag = value_a != value_b;
        let neq_12_flag = value_a_l != value_b_l;
        let neq_34_flag = value_a_h != value_b_h;

        // Calculate neq_{12,34}_flag_aux and its inverse mod M31
        let (neq_12_flag_aux, neq_12_flag_aux_inv) = if neq_12_flag {
            // When neq_12_flag == 1
            // value_a_[0] != value_b_[0] or value_a_[1] != value_b_[1]
            // neq_12_flag_aux = 1 / (value_a_l - value_b_l)
            // neq_12_flag_aux_inv = value_a_l - value_b_l
            let aux_inv = BaseField::from(value_a_l) - BaseField::from(value_b_l);
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        } else {
            let aux_inv = BaseField::from(pc_l.max(1));
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        };

        let (neq_34_flag_aux, neq_34_flag_aux_inv) = if neq_34_flag {
            // When neq_34_flag == 1
            // value_a_[2] != value_b_[2] or value_a_[3] != value_b_[3]
            // neq_34_flag_aux = 1 / (value_a_h - value_b_h)
            // neq_34_flag_aux_inv = value_a_h - value_b_h
            let aux_inv = BaseField::from(value_a_h) - BaseField::from(value_b_h);
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        } else {
            let aux_inv = BaseField::from(pc_h.max(1));
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        };

        let neq_aux = [neq_12_flag_aux, neq_34_flag_aux];
        let neq_aux_inv = [neq_12_flag_aux_inv, neq_34_flag_aux_inv];

        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            neq_flag,
            neq_12_flag,
            neq_34_flag,
            carry_bits,
            neq_aux,
            neq_aux_inv,
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
        let pc_next = u32_to_16bit_parts_le(step.next_pc);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let ExecutionResult {
            neq_flag,
            neq_12_flag,
            neq_34_flag,
            carry_bits,
            neq_aux,
            neq_aux_inv,
        } = Self::execute_step(program_step);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, program_step.get_value_a(), Column::AVal);
        trace.fill_columns(row_idx, program_step.get_value_b(), Column::BVal);

        trace.fill_columns(row_idx, neq_flag, Column::HNeqFlag);
        trace.fill_columns(row_idx, neq_12_flag, Column::HNeq12Flag);
        trace.fill_columns(row_idx, neq_34_flag, Column::HNeq34Flag);

        trace.fill_columns_base_field(row_idx, [neq_aux[0]].as_slice(), Column::HNeq12FlagAux);
        trace.fill_columns_base_field(row_idx, [neq_aux[1]].as_slice(), Column::HNeq34FlagAux);

        trace.fill_columns_base_field(
            row_idx,
            [neq_aux_inv[0]].as_slice(),
            Column::HNeq12FlagAuxInv,
        );
        trace.fill_columns_base_field(
            row_idx,
            [neq_aux_inv[1]].as_slice(),
            Column::HNeq34FlagAuxInv,
        );

        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
    }
}

impl<T: BranchOp> BuiltInComponent for BranchEq<T> {
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
        let mut local_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
            T::generate_trace_row(row_idx, &mut local_trace, program_step);
        }
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
            if T::OPCODE == BuiltinOpcode::BNE {
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
        ClkIncrement {
            is_local_pad: Column::IsLocalPad,
            clk: Column::Clk,
            clk_next: Column::ClkNext,
            clk_carry: Column::ClkCarry,
        }
        .constrain(eval, &trace_eval);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);

        let [h_neq_flag] = trace_eval!(trace_eval, Column::HNeqFlag);
        let [h_neq12_flag] = trace_eval!(trace_eval, Column::HNeq12Flag);
        let [h_neq12_flag_aux] = trace_eval!(trace_eval, Column::HNeq12FlagAux);
        let [h_neq34_flag] = trace_eval!(trace_eval, Column::HNeq34Flag);
        let [h_neq34_flag_aux] = trace_eval!(trace_eval, Column::HNeq34FlagAux);

        let [h_neq12_flag_aux_inv] = trace_eval!(trace_eval, Column::HNeq12FlagAuxInv);
        let [h_neq34_flag_aux_inv] = trace_eval!(trace_eval, Column::HNeq34FlagAuxInv);

        // skip the padding selector for some constraints to avoid increasing the constraint
        // degree bound, for such constraints providing all zeroes is sufficient on padding rows
        //
        // (1 − is-local-pad) · (
        //     (a-val(1) + 2^8 · a-val(2) − b-val(1) − 2^8 · b-val(2)) · h-neq12-flag-aux
        //     − h-neq12-flag
        // ) = 0
        eval.add_constraint(
            (a_val[0].clone() + a_val[1].clone() * BaseField::from(1 << 8)
                - b_val[0].clone()
                - b_val[1].clone() * BaseField::from(1 << 8))
                * h_neq12_flag_aux.clone()
                - h_neq12_flag.clone(),
        );

        // (1 − is-local-pad) · (
        //     (a-val(3) + 2^8 · a-val(4) − b-val(3) − 2^8 · b-val(4)) · h-neq34-flag-aux
        //     − h-neq34-flag
        // ) = 0
        eval.add_constraint(
            (a_val[2].clone() + a_val[3].clone() * BaseField::from(1 << 8)
                - b_val[2].clone()
                - b_val[3].clone() * BaseField::from(1 << 8))
                * h_neq34_flag_aux.clone()
                - h_neq34_flag.clone(),
        );

        // (h-neq12-flag) · (1 − h-neq12-flag) = 0
        eval.add_constraint(h_neq12_flag.clone() * (E::F::one() - h_neq12_flag.clone()));

        // (h-neq34-flag) · (1 − h-neq34-flag) = 0
        eval.add_constraint(h_neq34_flag.clone() * (E::F::one() - h_neq34_flag.clone()));

        // enforcing h-neq12-flag-aux != 0, h-neq34-flag-aux != 0
        //
        // (1 − is-local-pad) · (h-neq12-flag-aux · h-neq12-flag-aux-inv − 1) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_neq12_flag_aux.clone() * h_neq12_flag_aux_inv.clone() - E::F::one()),
        );
        // (1 − is-local-pad) · (h-neq34-flag-aux · h-neq34-flag-aux-inv − 1) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_neq34_flag_aux.clone() * h_neq34_flag_aux_inv.clone() - E::F::one()),
        );

        // (1 − is-local-pad) · (
        //     (1 − h-neq12-flag) · (1 − h-neq34-flag)
        //     − (1 − h-neq-flag)
        // ) = 0
        eval.add_constraint(
            (E::F::one() - h_neq12_flag.clone()) * (E::F::one() - h_neq34_flag.clone())
                - (E::F::one() - h_neq_flag.clone()),
        );

        let decoding_trace_eval =
            TraceEval::<EmptyPreprocessedColumn, T::DecodingColumn, E>::new(eval);
        let enforce_branch_flag = T::enforce_branch_flag_eval(&trace_eval);

        let c_val = type_b::CVal.eval(&decoding_trace_eval);
        let [h_carry_1, h_carry_2] = trace_eval!(trace_eval, Column::HCarry);
        // add two bytes at a time
        //
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

        T::constrain_decoding(eval, &trace_eval, &decoding_trace_eval);

        // Logup Interactions
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;
        let reg_addrs = T::combine_reg_addresses(&decoding_trace_eval);
        let instr_val = T::combine_instr_val(&decoding_trace_eval);

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            &trace_eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            reg_addrs,
            [a_val, b_val, zero_array::<WORD_SIZE, E>()],
            instr_val,
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
    fn assert_beq_constraints() {
        let instructions = &[
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Case 1: BEQ with different values (should not branch)
            // BEQ x1, x2, 0xff (branch to PC + 0xff if x1 == x2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 2, 0xff),
            // Case 2: BEQ with equal values (should branch)
            // BEQ x1, x3, 12 (should branch as x1 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 3, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BEQ with zero and non-zero (should not branch)
            // BEQ x0, x1, 0xff (branch to PC + 0xff if x0 == x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 0, 1, 0xff),
            // Case 4: BEQ with zero and zero (should branch)
            // BEQ x0, x0, 8 (should branch as x0 == x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 0, 0, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
        ];

        assert_branch_cmp_constraints(BEQ, instructions);
    }

    #[test]
    fn assert_bne_constraints() {
        let instructions = &[
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Case 1: BNE with equal values (should not branch)
            // BNE x1, x3, 0xff (should not branch as x1 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BNE), 1, 3, 0xff),
            // Case 2: BNE with different values (should branch)
            // BNE x1, x2, 12 (branch to PC + 12 if x1 != x2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BNE), 1, 2, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BNE with zero and non-zero (should branch)
            // BNE x0, x1, 8 (branch to PC + 8 if x0 != x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BNE), 0, 1, 8),
            // No-op instructions to fill the gap (should not be executed)
            Instruction::unimpl(),
            // Case 4: BNE with zero and zero (should not branch)
            // BNE x0, x0, 8 (should not branch as x0 == x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BNE), 0, 0, 8),
        ];

        assert_branch_cmp_constraints(BNE, instructions);
    }
}
