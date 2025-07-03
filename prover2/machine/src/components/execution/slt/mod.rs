use std::marker::PhantomData;

use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
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
    original_base_column,
    program::{ProgramStep, Word},
    trace_eval,
};

use crate::{
    components::{
        execution::decoding::{
            instruction_decoding_trace, InstructionDecoding, VirtualDecodingColumn,
        },
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
mod slt;
mod slti;

use columns::{Column, PreprocessedColumn};

pub const SLT: Slt<slt::Slt> = Slt::new();
pub const SLTI: Slt<slti::Slti> = Slt::new();

pub trait SltOp:
    InstructionDecoding<PreprocessedColumn = PreprocessedColumn, MainColumn = Column>
{
}

pub struct Slt<S> {
    _phantom: PhantomData<S>,
}

struct ExecutionResult {
    pub borrow_bits: [bool; 2], // for 16-bit boundaries
    pub diff_bytes: Word,
}

impl<S: SltOp> Slt<S> {
    const REG1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const REG3_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const REG3_WRITE: BaseField = BaseField::from_u32_unchecked(1);

    const fn new() -> Self {
        assert!(matches!(
            S::OPCODE,
            BuiltinOpcode::SLT | BuiltinOpcode::SLTI
        ));
        Self {
            _phantom: PhantomData,
        }
    }

    fn iter_program_steps<'a>(
        &self,
        side_note: &SideNote<'a>,
    ) -> impl Iterator<Item = ProgramStep<'a>> {
        let slt_opcode = S::OPCODE;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                opcode if opcode == Some(slt_opcode),
            )
        })
    }

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
        _side_note: &mut SideNote,
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

        let result = program_step
            .get_result()
            .unwrap_or_else(|| panic!("{} instruction must have result", S::OPCODE));

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, result[0], Column::AVal);
        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &value_c, Column::CVal);

        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);
        trace.fill_columns(row_idx, diff_bytes, Column::HRem);

        trace.fill_columns(row_idx, value_b[WORD_SIZE - 1] & 0x7F, Column::HRemB);
        trace.fill_columns(row_idx, value_c[WORD_SIZE - 1] & 0x7F, Column::HRemC);

        trace.fill_columns(row_idx, program_step.get_sgn_b(), Column::HSgnB);
        trace.fill_columns(row_idx, program_step.get_sgn_c(), Column::HSgnC);
    }
}

impl<S: SltOp> BuiltInComponent for Slt<S> {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

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
        let num_add_steps = self.iter_program_steps(side_note).count();
        let log_size = num_add_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut local_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in self.iter_program_steps(side_note).enumerate() {
            self.generate_trace_row(&mut common_trace, row_idx, program_step, side_note);
            S::generate_trace_row(row_idx, &mut local_trace, program_step);
        }
        // fill padding
        for row_idx in num_add_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
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
            Column::COLUMNS_NUM + S::DecodingColumn::COLUMNS_NUM
        );
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);
        let pc = original_base_column!(component_trace, Column::Pc);

        let [a_val] = original_base_column!(component_trace, Column::AVal);
        let b_val = original_base_column!(component_trace, Column::BVal);
        let c_val = original_base_column!(component_trace, Column::CVal);

        let clk_next = original_base_column!(component_trace, Column::ClkNext);
        let pc_next = original_base_column!(component_trace, Column::PcNext);

        let decoding_trace = instruction_decoding_trace(
            component_trace.log_size(),
            self.iter_program_steps(side_note),
        );
        let instr_val = original_base_column!(decoding_trace, VirtualDecodingColumn::InstrVal);

        let [op_a] = original_base_column!(decoding_trace, VirtualDecodingColumn::OpA);
        let [op_b] = original_base_column!(decoding_trace, VirtualDecodingColumn::OpB);
        let [op_c] = original_base_column!(decoding_trace, VirtualDecodingColumn::OpC);

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_prog_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        );
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        logup_trace_builder.add_to_relation_with(
            &rel_cont_prog_exec,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[clk_next, pc_next].concat(),
        );

        let reg2_accessed = BaseField::from(S::REG2_ACCESSED as u32);
        let mut a_val = vec![a_val];
        a_val.resize(WORD_SIZE, BaseField::zero().into());
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         op-a, op-b, op-c,
        //         a-val, b-val, c-val,
        //         reg1-accessed, reg2-accessed, reg3-accessed,
        //         reg3-write
        //     )
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &[op_a, op_b, op_c],
                &a_val,
                &b_val,
                &c_val,
                &[
                    Self::REG1_ACCESSED.into(),
                    reg2_accessed.into(),
                    Self::REG3_ACCESSED.into(),
                    Self::REG3_WRITE.into(),
                ],
            ]
            .concat(),
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

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = trace_eval!(trace_eval, Column::ClkNext);

        let h_rem = trace_eval!(trace_eval, Column::HRem);

        let [a_val] = trace_eval!(trace_eval, Column::AVal);
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
                * (h_rem[0].clone() + h_rem[1].clone() * modulus.clone()
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
                * (h_rem[2].clone() + h_rem[3].clone() * modulus.clone()
                    - h_borrow_2.clone() * modulus.clone().pow(2)
                    - (b_val[2].clone() + b_val[3].clone() * modulus.clone()
                        - c_val[2].clone()
                        - c_val[3].clone() * modulus.clone()
                        - h_borrow_1.clone())),
        );

        let [h_rem_b] = trace_eval!(trace_eval, Column::HRemB);
        let [h_rem_c] = trace_eval!(trace_eval, Column::HRemC);
        let [h_sgn_b] = trace_eval!(trace_eval, Column::HSgnB);
        let [h_sgn_c] = trace_eval!(trace_eval, Column::HSgnC);

        // (1 − is-local-pad) · (h-rem-b + h-sgn-b · 2^7 − b-val(4) ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem_b.clone() + h_sgn_b.clone() * BaseField::from(1 << 7) - b_val[3].clone()),
        );
        // (1 − is-local-pad) · (h-rem-c + h-sgn-c · 2^7 − c-val(4) ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem_c.clone() + h_sgn_c.clone() * BaseField::from(1 << 7) - c_val[3].clone()),
        );

        // (1 − is-local-pad) · (
        //     (h-sgn-b)(1 − h-sgn-c)
        //     + h-ltu-flag · (
        //         (h-sgn-b)(h-sgn-c) + (1 − h-sgn-b)(1 − h-sgn-c)
        //     )
        //     − a-val(1)
        // ) = 0
        let h_ltu_flag = &h_borrow_2;
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_sgn_b.clone() * (E::F::one() - h_sgn_c.clone())
                    + h_ltu_flag.clone()
                        * (h_sgn_b.clone() * h_sgn_c.clone()
                            + (E::F::one() - h_sgn_b.clone()) * (E::F::one() - h_sgn_c.clone()))
                    - a_val.clone()),
        );

        let local_trace_eval = TraceEval::new(eval);
        S::constrain_decoding(eval, &trace_eval, &local_trace_eval);

        // Logup Interactions
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;

        let instr_val = S::combine_instr_val(&local_trace_eval);
        let reg_addrs = S::combine_reg_addresses(&local_trace_eval);

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_prog_memory,
            (is_local_pad.clone() - E::F::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        ));
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        eval.add_to_relation(RelationEntry::new(
            rel_cont_prog_exec,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk_next[0].clone(),
                clk_next[1].clone(),
                pc_next[0].clone(),
                pc_next[1].clone(),
            ],
        ));

        let reg2_accessed = E::F::from(BaseField::from(S::REG2_ACCESSED as u32));
        let mut a_val = vec![a_val];
        a_val.resize(WORD_SIZE, E::F::zero());
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         op-a, op-b, op-c,
        //         a-val, b-val, c-val,
        //         reg1-accessed, reg2-accessed, reg3-accessed,
        //         reg3-write
        //     )
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &reg_addrs,
                &a_val,
                &b_val,
                &c_val,
                &[
                    Self::REG1_ACCESSED.into(),
                    reg2_accessed,
                    Self::REG3_ACCESSED.into(),
                    Self::REG3_WRITE.into(),
                ],
            ]
            .concat(),
        ));

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
    fn assert_slt_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // x1 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5),
            // x2 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 10),
            // x3 = -5 (0xFFFF_FFFB)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, -5i32 as u32),
            // x4 = -1 (0xFFFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, -1i32 as u32),
            // SLT tests
            //
            // x5 = (x1 < x2) -> 1   // 5 < 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 5, 1, 2),
            // x6 = (x2 < x1) -> 0   // 10 < 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 6, 2, 1),
            // x7 = (x3 < x2) -> 1   // -5 < 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 7, 3, 2),
            // x8 = (x2 < x3) -> 0   // 10 < -5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 8, 2, 3),
            // x9 = (x3 < x4) -> 1   // -5 < -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 9, 3, 4),
            // x10 = (x4 < x3) -> 0  // -1 < -5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 10, 4, 3),
            // SLTI tests
            //
            // x11 = (x1 < 10) => 1   // 5 < 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTI), 11, 1, 10),
            // x12 = (x2 < 5) => 0    // 10 < 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTI), 12, 2, 5),
            // x13 = (x3 < 0) => 1    // -5 < 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTI), 13, 3, 0),
            // x14 = (x1 < -1) => 0   // 5 < -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTI), 14, 1, -1i32 as u32),
            // x15 = (x4 < -5) => 0   // -1 < -5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTI), 15, 4, -5i32 as u32),
            // x16 = (x3 < -1) => 1   // -5 < -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTI), 16, 3, -1i32 as u32),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(SLT, assert_ctx);
        claimed_sum += assert_component(SLTI, assert_ctx);

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
