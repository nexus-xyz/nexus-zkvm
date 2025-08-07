use std::marker::PhantomData;

use num_traits::One;
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
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
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::{ExecutionComponent, ExecutionLookupEval},
            decoding::InstructionDecoding,
        },
        utils::{
            add_16bit_with_carry,
            constraints::{ClkIncrement, PcIncrement},
            u32_to_16bit_parts_le,
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

mod columns;
mod sll;
mod slli;

use columns::{Column, PreprocessedColumn};

pub const SLL: Sll<sll::Sll> = Sll::new();
pub const SLLI: Sll<slli::Slli> = Sll::new();

pub trait SllOp:
    InstructionDecoding<PreprocessedColumn = PreprocessedColumn, MainColumn = Column>
{
}

pub struct Sll<T> {
    _phantom: PhantomData<T>,
}

impl<T: SllOp> ExecutionComponent for Sll<T> {
    const OPCODE: BuiltinOpcode = <T as InstructionDecoding>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = <T as InstructionDecoding>::REG2_ACCESSED;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;
}

struct ExecutionResult {
    shift_bits: [u8; 5],
    exp1_3: u8,
    h1: u8,
    rem: Word,
    qt: Word,
}

impl<T: SllOp> Sll<T> {
    const fn new() -> Self {
        assert!(matches!(
            T::OPCODE,
            BuiltinOpcode::SLL | BuiltinOpcode::SLLI
        ));
        Self {
            _phantom: PhantomData,
        }
    }

    fn execute_step(value_b: Word, value_c: Word) -> ExecutionResult {
        let imm = value_c[0];

        let h1 = imm >> 5;
        let exp1_3 = 1 << (imm & 0b111);
        let mut sh = [0; 5];
        for (i, sh) in sh.iter_mut().enumerate() {
            *sh = (imm >> i) & 1;
        }

        let mut rem = [0u8; WORD_SIZE];
        let mut qt = [0u8; WORD_SIZE];

        let t = u16::from(value_b[0]) * u16::from(exp1_3);
        rem[0] = (t & 0xFF) as _;
        qt[0] = (t >> 8) as _;

        for i in 1..WORD_SIZE {
            let t = u16::from(value_b[i]) * u16::from(exp1_3) + qt[i - 1] as u16;
            rem[i] = (t & 0xFF) as _;
            qt[i] = (t >> 8) as _;
        }

        ExecutionResult {
            shift_bits: sh,
            exp1_3,
            h1,
            rem,
            qt,
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
        let (_pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (_clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let result = program_step
            .get_result()
            .unwrap_or_else(|| panic!("{} instruction must have result", T::OPCODE));
        let ExecutionResult {
            shift_bits,
            exp1_3,
            h1,
            rem,
            qt,
        } = Self::execute_step(value_b, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &result, Column::AVal);

        trace.fill_columns_bytes(row_idx, &shift_bits, Column::Sh);
        trace.fill_columns(row_idx, exp1_3, Column::Exp3);
        trace.fill_columns(row_idx, h1, Column::HRem);
        trace.fill_columns(row_idx, rem, Column::Rem);
        trace.fill_columns(row_idx, qt, Column::Qt);

        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
    }
}

impl<T: SllOp> BuiltInComponent for Sll<T> {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

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
        let mut decoding_trace = TraceBuilder::new(log_size);
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
                &mut decoding_trace,
                program_step,
                &mut range_check_accum,
            );
        }
        side_note.range_check.append(range_check_accum);
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
            Column::COLUMNS_NUM + T::DecodingColumn::COLUMNS_NUM
        );
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let [h_rem] = original_base_column!(component_trace, Column::HRem);
        let rem = original_base_column!(component_trace, Column::Rem);
        let qt = original_base_column!(component_trace, Column::Qt);

        for word in [rem, qt] {
            range_check.range256.generate_logup_col(
                &mut logup_trace_builder,
                is_local_pad.clone(),
                &word,
            );
        }
        range_check
            .range8
            .generate_logup_col(&mut logup_trace_builder, is_local_pad, h_rem);

        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);
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
        let decoding_trace_eval = TraceEval::new(eval);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = T::combine_c_val(&decoding_trace_eval);

        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = ClkIncrement {
            clk: Column::Clk,
            clk_carry: Column::ClkCarry,
        }
        .eval(eval, &trace_eval);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = PcIncrement {
            pc: Column::Pc,
            pc_carry: Column::PcCarry,
        }
        .eval(eval, &trace_eval);

        let sh = trace_eval!(trace_eval, Column::Sh);
        let qt = trace_eval!(trace_eval, Column::Qt);
        let rem = trace_eval!(trace_eval, Column::Rem);

        let [h_rem] = trace_eval!(trace_eval, Column::HRem);
        let [exp3] = trace_eval!(trace_eval, Column::Exp3);

        // (1 − is-local-pad) · (
        //     sh1 + sh2 · 2 + sh3 · 2^2 + sh4 · 2^3 + sh5 · 2^4 + h-rem · 2^5 − c-val(1)
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (sh[0].clone()
                    + sh[1].clone() * BaseField::from(1 << 1)
                    + sh[2].clone() * BaseField::from(1 << 2)
                    + sh[3].clone() * BaseField::from(1 << 3)
                    + sh[4].clone() * BaseField::from(1 << 4)
                    + h_rem.clone() * BaseField::from(1 << 5)
                    - c_val[0].clone()),
        );
        // (sh1) · (1 − sh1) = 0
        // (sh2) · (1 − sh2) = 0
        // (sh3) · (1 − sh3) = 0
        // (sh4) · (1 − sh4) = 0
        // (sh5) · (1 − sh5) = 0
        for sh in &sh {
            eval.add_constraint((E::F::one() - sh.clone()) * sh.clone());
        }
        // (1 − is-local-pad) · (
        //     (sh1 + 1)
        //     · ((2^2 − 1) · sh2 + 1)
        //     · ((2^4 − 1) · sh3 + 1)
        //     − exp3
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * ((sh[0].clone() + E::F::one())
                    * (sh[1].clone() * BaseField::from((1 << 2) - 1) + E::F::one())
                    * (sh[2].clone() * BaseField::from((1 << 4) - 1) + E::F::one())
                    - exp3.clone()),
        );

        // (1 − is-local-pad) · (rem1 + qt1 · 2^8 − b-val(1) · exp3) = 0
        // (1 − is-local-pad) · (rem2 + qt2 · 2^8 − qt1 − b-val(2) · exp3) = 0
        // (1 − is-local-pad) · (rem3 + qt3 · 2^8 − qt2 − b-val(3) · exp3) = 0
        // (1 − is-local-pad) · (rem4 + qt4 · 2^8 − qt3 − b-val(4) · exp3) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (rem[0].clone() + qt[0].clone() * BaseField::from(1 << 8)
                    - b_val[0].clone() * exp3.clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                (E::F::one() - is_local_pad.clone())
                    * (rem[i].clone() + qt[i].clone() * BaseField::from(1 << 8)
                        - qt[i - 1].clone()
                        - b_val[i].clone() * exp3.clone()),
            );
        }

        // (1 − is-local-pad) · (a-val(1) − rem1 · (1 − sh4) · (1 − sh5)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[0].clone()
                    - rem[0].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())),
        );
        // (1 − is-local-pad) · (a-val(2) − rem2 · (1 − sh4) · (1 − sh5) − rem1 · sh4 · (1 − sh5)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[1].clone()
                    - rem[1].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                    - rem[0].clone() * sh[3].clone() * (E::F::one() - sh[4].clone())),
        );
        // (1 − is-local-pad) · (a-val(3) − rem3 · (1 − sh4) · (1 − sh5) − rem2 · sh4 · (1 − sh5) − rem1 · (1 − sh4) · sh5) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[2].clone()
                    - rem[2].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                    - rem[1].clone() * sh[3].clone() * (E::F::one() - sh[4].clone())
                    - rem[0].clone() * (E::F::one() - sh[3].clone()) * sh[4].clone()),
        );
        // (1 − is-local-pad) · (a-val(4) − rem4 · (1 − sh4) · (1 − sh5) − rem3 · sh4 · (1 − sh5) − rem2 · (1 − sh4) · sh5 − rem1 · sh4 · sh5) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[3].clone()
                    - rem[3].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                    - rem[2].clone() * sh[3].clone() * (E::F::one() - sh[4].clone())
                    - rem[1].clone() * (E::F::one() - sh[3].clone()) * sh[4].clone()
                    - rem[0].clone() * sh[3].clone() * sh[4].clone()),
        );

        // range checks
        for word in [rem, qt] {
            range_check
                .range256
                .constrain(eval, is_local_pad.clone(), &word);
        }
        range_check
            .range8
            .constrain(eval, is_local_pad.clone(), h_rem);

        T::constrain_decoding(eval, &trace_eval, &decoding_trace_eval, range_check);

        // Logup Interactions
        let instr_val = T::combine_instr_val(&decoding_trace_eval);
        let reg_addrs = T::combine_reg_addresses(&decoding_trace_eval);

        let c_val = if Self::REG2_ACCESSED {
            c_val
        } else {
            zero_array::<WORD_SIZE, E>()
        };

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
                reg_values: [a_val, b_val, c_val],
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

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
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
    fn assert_sll_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 3),
            // x3 = 255 (0xFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 255),
            // SLL
            //
            // x4 = x1 << x2 = 1 << 3 = 8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLL), 4, 1, 2),
            // x5 = x3 << 1 = 0xFF << 1 = 0x1FE
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLL), 6, 3, 5),
            // x7 = x3 << 31 → shift by maximum legal amount
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 31),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLL), 8, 3, 7),
            // SLLI
            //
            // x9 = x1 << 3 = 1 << 3 = 8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 9, 1, 3),
            // x10 = x3 << 1 = 0xFF << 1 = 0x1FE
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 10, 3, 1),
            // x11 = x3 << 31
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 11, 3, 31),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(SLL, assert_ctx);
        claimed_sum += assert_component(SLLI, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
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
