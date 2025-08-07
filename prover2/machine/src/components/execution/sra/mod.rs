use std::marker::PhantomData;

use num_traits::{Euclid, One};
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
mod sra;
mod srai;

use columns::{Column, PreprocessedColumn};

pub const SRA: Sra<sra::Sra> = Sra::new();
pub const SRAI: Sra<srai::Srai> = Sra::new();

pub trait SraOp:
    InstructionDecoding<PreprocessedColumn = PreprocessedColumn, MainColumn = Column>
{
}

pub struct Sra<T> {
    _phantom: PhantomData<T>,
}

impl<T: SraOp> ExecutionComponent for Sra<T> {
    const OPCODE: BuiltinOpcode = <T as InstructionDecoding>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = <T as InstructionDecoding>::REG2_ACCESSED;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;
}

struct ExecutionResult {
    srl: Word,
    shift_bits: [u8; 5],
    exp1_3: u8,
    h1: u8,
    h2: u8,
    rem: Word,
    rem_diff: Word,
    qt: Word,
}

impl<T: SraOp> Sra<T> {
    const fn new() -> Self {
        assert!(matches!(
            T::OPCODE,
            BuiltinOpcode::SRA | BuiltinOpcode::SRAI
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
        let mut rem_diff = [0u8; WORD_SIZE];
        let mut qt = [0u8; WORD_SIZE];
        let srl = u32::from_le_bytes(value_b) >> (imm & 0x1F);

        (qt[3], rem[3]) = value_b[3].div_rem_euclid(&exp1_3);
        for i in (0..WORD_SIZE - 1).rev() {
            let t = u16::from(value_b[i]) + (u16::from(rem[i + 1]) << 8);
            let (q, r) = t.div_rem_euclid(&(exp1_3 as u16));
            // It is guaranteed that q, r < 256
            rem[i] = r as u8;
            qt[i] = q as u8;
        }
        let h2 = value_b[3] & 0b0111_1111;

        for i in 0..WORD_SIZE {
            rem_diff[i] = exp1_3 - 1 - rem[i];
        }

        ExecutionResult {
            srl: srl.to_le_bytes(),
            shift_bits: sh,
            exp1_3,
            h1,
            h2,
            rem,
            rem_diff,
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
            srl,
            shift_bits,
            exp1_3,
            h1,
            h2,
            rem,
            rem_diff,
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
        trace.fill_columns(row_idx, h2, Column::HRemB);
        trace.fill_columns(row_idx, rem, Column::Rem);
        trace.fill_columns(row_idx, rem_diff, Column::RemAux);
        trace.fill_columns(row_idx, qt, Column::Qt);
        trace.fill_columns(row_idx, srl, Column::Srl);

        let sgn_b = program_step.get_sgn_b();
        let exp = BaseField::from(256u32 / u32::from(exp1_3));
        let sra_mask = BaseField::from(sgn_b as u32) * BaseField::from(exp1_3 as u32 - 1) * exp;

        trace.fill_columns(row_idx, sgn_b, Column::HSgnB);
        trace.fill_columns(row_idx, exp, Column::Exp3Aux);
        trace.fill_columns(row_idx, sra_mask, Column::SraMask);

        range_check_accum.range256.add_values(&rem);
        range_check_accum.range256.add_values(&rem_diff);
        range_check_accum.range256.add_values(&qt);
        range_check_accum.range8.add_value(h1);
        range_check_accum.range128.add_value(h2);
    }
}

impl<T: SraOp> BuiltInComponent for Sra<T> {
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
        let [h_rem_b] = original_base_column!(component_trace, Column::HRemB);
        let rem = original_base_column!(component_trace, Column::Rem);
        let rem_aux = original_base_column!(component_trace, Column::RemAux);
        let qt = original_base_column!(component_trace, Column::Qt);
        // range checks
        for word in [rem, rem_aux, qt] {
            range_check.range256.generate_logup_col(
                &mut logup_trace_builder,
                is_local_pad.clone(),
                &word,
            );
        }
        range_check.range8.generate_logup_col(
            &mut logup_trace_builder,
            is_local_pad.clone(),
            h_rem,
        );
        range_check.range128.generate_logup_col(
            &mut logup_trace_builder,
            is_local_pad.clone(),
            h_rem_b,
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
        let rem_aux = trace_eval!(trace_eval, Column::RemAux);
        let srl = trace_eval!(trace_eval, Column::Srl);

        let [h_rem] = trace_eval!(trace_eval, Column::HRem);
        let [h_rem_b] = trace_eval!(trace_eval, Column::HRemB);
        let [h_sgn_b] = trace_eval!(trace_eval, Column::HSgnB);
        let [exp3] = trace_eval!(trace_eval, Column::Exp3);
        let [exp3_aux] = trace_eval!(trace_eval, Column::Exp3Aux);
        let [sra_mask] = trace_eval!(trace_eval, Column::SraMask);

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

        // extracting sign bit from b-val for arithmetic right shift
        //
        // (1 − is-local-pad) · (h-rem-b + h-sgn-b · 2^7 − b-val(4) ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem_b.clone() + h_sgn_b.clone() * BaseField::from(1 << 7) - b_val[3].clone()),
        );
        // (h-sgn-b) · (1 − h-sgn-b) = 0
        eval.add_constraint(h_sgn_b.clone() * (E::F::one() - h_sgn_b.clone()));

        // exp3 · exp3-aux = 2^8
        //
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
        // (1 − is-local-pad) · (
        //     2
        //     · (2 − sh1)
        //     · (2^2 − (2^2 − 1) · sh2)
        //     · (2^4 − (2^4 − 1) · sh3)
        //     − exp3-aux
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (E::F::from(BaseField::from(2))
                    * (E::F::from(BaseField::from(2)) - sh[0].clone())
                    * (E::F::from(BaseField::from(1 << 2))
                        - sh[1].clone() * BaseField::from((1 << 2) - 1))
                    * (E::F::from(BaseField::from(1 << 4))
                        - sh[2].clone() * BaseField::from((1 << 4) - 1))
                    - exp3_aux.clone()),
        );

        // (1 − is-local-pad) · (b-val(4) − rem4 − qt4 · exp3) = 0
        // (1 − is-local-pad) · (b-val(3) + rem4 · 2^8 − rem3 − qt3 · exp3) = 0
        // (1 − is-local-pad) · (b-val(2) + rem3 · 2^8 − rem2 − qt2 · exp3) = 0
        // (1 − is-local-pad) · (b-val(1) + rem2 · 2^8 − rem1 − qt1 · exp3) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (b_val[3].clone() - rem[3].clone() - qt[3].clone() * exp3.clone()),
        );
        for i in (0..WORD_SIZE - 1).rev() {
            eval.add_constraint(
                (E::F::one() - is_local_pad.clone())
                    * (b_val[i].clone() + rem[i + 1].clone() * BaseField::from(1 << 8)
                        - rem[i].clone()
                        - qt[i].clone() * exp3.clone()),
            );
        }

        // (1 − is-local-pad) · (exp3 − 1 − rem1 − rem1-aux) = 0
        // (1 − is-local-pad) · (exp3 − 1 − rem2 − rem2-aux) = 0
        // (1 − is-local-pad) · (exp3 − 1 − rem3 − rem3-aux) = 0
        // (1 − is-local-pad) · (exp3 − 1 − rem4 − rem4-aux) = 0
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                (E::F::one() - is_local_pad.clone())
                    * (exp3.clone() - E::F::one() - rem[i].clone() - rem_aux[i].clone()),
            );
        }

        // computing final logical right shift using remaining bits of the shift amount

        // (1 − is-local-pad) · (srl4 − qt4 · (1 − sh4) · (1 − sh5)) = 0
        // (1 − is-local-pad) · (srl3 − qt3 · (1 − sh4) · (1 − sh5) − qt4 · sh4 · (1 − sh5)) = 0
        // (1 − is-local-pad) · (srl2 − qt2 · (1 − sh4) · (1 − sh5) − qt3 · sh4 · (1 − sh5) − qt4 · (1 − sh4) · sh5) = 0
        // (1 − is-local-pad) · (srl1 − qt1 · (1 − sh4) · (1 − sh5) − qt2 · sh4 · (1 − sh5) − qt3 · (1 − sh4) · sh5 − qt4 · sh4 · sh5) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (srl[3].clone()
                    - qt[3].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (srl[2].clone()
                    - qt[2].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                    - qt[3].clone() * sh[3].clone() * (E::F::one() - sh[4].clone())),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (srl[1].clone()
                    - qt[1].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                    - qt[2].clone() * sh[3].clone() * (E::F::one() - sh[4].clone())
                    - qt[3].clone() * (E::F::one() - sh[3].clone()) * sh[4].clone()),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (srl[0].clone()
                    - qt[0].clone()
                        * (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                    - qt[1].clone() * sh[3].clone() * (E::F::one() - sh[4].clone())
                    - qt[2].clone() * (E::F::one() - sh[3].clone()) * sh[4].clone()
                    - qt[3].clone() * sh[3].clone() * sh[4].clone()),
        );

        // computing auxiliary mask for the replication of the sign bit
        // (1 − is-local-pad) · (h-sgn-b · (exp3 − 1) · exp3-aux − sra-mask) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_sgn_b.clone() * (exp3.clone() - E::F::one()) * exp3_aux.clone()
                    - sra_mask.clone()),
        );

        // replicating sign bit into vacated positions during logical right shift

        // (1 − is-local-pad) · (a-val(4) − (1 − sh4) · (1 − sh5) · (srl4 + sra-mask) − (sh4 + sh5 − sh4 · sh5) · h-sgn-b · (2^8 − 1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[3].clone()
                    - (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                        * (srl[3].clone() + sra_mask.clone())
                    - (sh[3].clone() + sh[4].clone() - sh[3].clone() * sh[4].clone())
                        * h_sgn_b.clone()
                        * (BaseField::from((1 << 8) - 1))),
        );
        // (1 − is-local-pad) · (a-val(3) − (1 − sh4) · (1 − sh5) · srl3 − sh4 · (1 − sh5) · (srl3 + sra-mask) − sh5 · h-sgn-b · (2^8 − 1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[2].clone()
                    - (E::F::one() - sh[3].clone())
                        * (E::F::one() - sh[4].clone())
                        * srl[2].clone()
                    - sh[3].clone()
                        * (E::F::one() - sh[4].clone())
                        * (srl[2].clone() + sra_mask.clone())
                    - sh[4].clone() * h_sgn_b.clone() * BaseField::from((1 << 8) - 1)),
        );
        // (1 − is-local-pad) · (a-val(2) − (1 − sh5) · srl2 − (1 − sh4) · sh5 · (srl2 + sra-mask) − sh4 · sh5 · h-sgn-b · (2^8 − 1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[1].clone()
                    - (E::F::one() - sh[4].clone()) * srl[1].clone()
                    - (E::F::one() - sh[3].clone())
                        * sh[4].clone()
                        * (srl[1].clone() + sra_mask.clone())
                    - sh[3].clone()
                        * sh[4].clone()
                        * h_sgn_b.clone()
                        * BaseField::from((1 << 8) - 1)),
        );
        // (1 − is-local-pad) · (a-val(1) − (1 − sh4 · sh5) · srl1 − sh4 · sh5 · (srl1 + sra-mask)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[0].clone()
                    - (E::F::one() - sh[3].clone() * sh[4].clone()) * srl[0].clone()
                    - sh[3].clone() * sh[4].clone() * (srl[0].clone() + sra_mask.clone())),
        );

        // range checks
        for word in [rem, rem_aux, qt] {
            range_check
                .range256
                .constrain(eval, is_local_pad.clone(), &word);
        }
        range_check
            .range8
            .constrain(eval, is_local_pad.clone(), h_rem);
        range_check
            .range128
            .constrain(eval, is_local_pad.clone(), h_rem_b);

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
            RegisterMemoryBoundary, ADDI, RANGE128, RANGE16, RANGE256, RANGE64, RANGE8, SLLI, SUB,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_sra_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 4),
            // Set x9 = 0x80000000 (most significant bit set, representing -2^31)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 9, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 9, 9, 31),
            // x10 = x9 >> 1 using SRA (should be 0xC0000000, preserving sign)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 10, 9, 1),
            // x11 = x9 >> 4 using SRA (should be 0xF8000000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 11, 9, 4),
            // Set x12 = -20 (testing negative numbers with SRA)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 12, 0, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 12, 0, 12),
            // x13 = x12 >> 2 using SRA (-20 >> 2 = -5)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 13, 12, 2),
            // Testing SRAI (Shift Right Arithmetic Immediate)
            // x14 = x9 >> 16 using SRAI (should be 0xFFFF8000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 14, 9, 16),
            // Set x15 = 0x7FFFFFFF (maximum positive 32-bit integer)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 15, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 15, 15, 31),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 15, 15, 1),
            // x16 = x15 >> 1 using SRAI (should be 0x3FFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 16, 15, 1),
            // x17 = x15 >> 31 using SRAI (should be 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 17, 15, 31),
            // x9 = x17 >> 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 9, 17, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 9, 17, 0),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(SRA, assert_ctx);
        claimed_sum += assert_component(SRAI, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &ADDI,
                &SUB,
                &SLLI,
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
}
