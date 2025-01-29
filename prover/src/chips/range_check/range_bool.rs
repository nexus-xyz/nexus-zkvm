// This file contains range-checking for columns containing only {0, 1}

use stwo_prover::constraint_framework::logup::LookupElements;

use num_traits::One;

use crate::{
    column::{
        Column::{
            self, BorrowFlag, CH1Minus, CH2Minus, CH3Minus, CarryFlag, ImmB, ImmC, IsAdd, IsAnd,
            IsAuipc, IsBge, IsBgeu, IsBlt, IsBltu, IsJal, IsJalr, IsLb, IsLbu, IsLh, IsLhu, IsLui,
            IsLw, IsOr, IsPadding, IsSb, IsSh, IsSll, IsSlt, IsSltu, IsSra, IsSrl, IsSub, IsSw,
            IsXor, LtFlag, OpA0, OpB0, OpC11, OpC20, OpC4, PcCarry, Ram1Accessed, Ram2Accessed,
            Ram3Accessed, Ram4Accessed, RamInitFinalFlag, Reg1Accessed, Reg2Accessed, Reg3Accessed,
            RemAux, SgnA, SgnB, SgnC, ShiftBit1, ShiftBit2, ShiftBit3, ShiftBit4, ShiftBit5,
            ValueAEffectiveFlag,
        },
        ProgramColumn,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{program_trace_eval, TraceEval},
        program_trace::ProgramTracesBuilder,
        sidenote::SideNote,
        ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
    WORD_SIZE,
};

/// A Chip for range-checking values for {0, 1}
///
/// RangeBoolChip can be located anywhere in the chip composition.

pub struct RangeBoolChip;

const CHECKED_SINGLE: [Column; 48] = [
    ValueAEffectiveFlag,
    ImmB,
    ImmC,
    IsAdd,
    IsOr,
    IsAnd,
    IsXor,
    IsSub,
    IsSltu,
    IsSlt,
    IsBltu,
    IsBlt,
    IsBgeu,
    IsBge,
    IsJal,
    IsSb,
    IsSh,
    IsSw,
    IsLb,
    IsLh,
    IsLbu,
    IsLhu,
    IsLw,
    IsLui,
    IsAuipc,
    IsJalr,
    IsSll,
    IsSrl,
    IsSra,
    IsPadding,
    LtFlag,
    RemAux,
    SgnA,
    SgnB,
    SgnC,
    Reg1Accessed,
    Reg2Accessed,
    Reg3Accessed,
    Ram1Accessed,
    Ram2Accessed,
    Ram3Accessed,
    Ram4Accessed,
    ShiftBit1,
    ShiftBit2,
    ShiftBit3,
    ShiftBit4,
    ShiftBit5,
    RamInitFinalFlag,
];
const CHECKED_WORD: [Column; 6] = [CarryFlag, BorrowFlag, CH1Minus, CH2Minus, CH3Minus, PcCarry];
const TYPE_R_CHECKED_SINGLE: [Column; 3] = [OpC4, OpA0, OpB0];
const TYPE_I_NO_SHIFT_SINGLE: [Column; 3] = [OpC11, OpA0, OpB0];
const TYPE_I_SHIFT_SINGLE: [Column; 3] = [OpC4, OpA0, OpB0];
const TYPE_J_CHECKED_SINGLE: [Column; 3] = [OpC11, OpC20, OpA0];

// TODO: also range-check PrgMemoryFlag in program trace

impl MachineChip for RangeBoolChip {
    fn fill_main_trace(
        _traces: &mut TracesBuilder,
        _row_idx: usize,
        _step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
        _side_note: &mut SideNote,
    ) {
        // Intentionally empty. Logup isn't used.
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        for col in CHECKED_SINGLE.into_iter() {
            let [col] = trace_eval.column_eval(col);
            eval.add_constraint(col.clone() * (col - E::F::one()));
        }

        let [type_r] = virtual_column::IsTypeR::eval(trace_eval);
        for col in TYPE_R_CHECKED_SINGLE.into_iter() {
            let [col] = trace_eval.column_eval(col);
            eval.add_constraint(type_r.clone() * col.clone() * (col - E::F::one()));
        }

        let [is_type_i_no_shift] = virtual_column::IsTypeINoShift::eval(trace_eval);
        for col in TYPE_I_NO_SHIFT_SINGLE {
            let [col] = trace_eval.column_eval(col);
            eval.add_constraint(is_type_i_no_shift.clone() * col.clone() * (col - E::F::one()));
        }

        let [is_alu_imm_shift] = virtual_column::IsAluImmShift::eval(trace_eval);
        for col in TYPE_I_SHIFT_SINGLE {
            let [col] = trace_eval.column_eval(col);
            eval.add_constraint(is_alu_imm_shift.clone() * col.clone() * (col - E::F::one()));
        }

        let [is_type_j] = virtual_column::IsTypeJ::eval(trace_eval);
        for col in TYPE_J_CHECKED_SINGLE {
            let [col] = trace_eval.column_eval(col);
            eval.add_constraint(is_type_j.clone() * col.clone() * (col - E::F::one()));
        }

        for col_word in CHECKED_WORD.into_iter() {
            let col_word = trace_eval.column_eval::<WORD_SIZE>(col_word);
            for limb in col_word.into_iter() {
                eval.add_constraint(limb.clone() * (limb - E::F::one()));
            }
        }
        let [prg_memory_flg] = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryFlag);
        eval.add_constraint(prg_memory_flg.clone() * (prg_memory_flg - E::F::one()));
        let [pub_input_flg] = program_trace_eval!(trace_eval, ProgramColumn::PublicInputFlag);
        eval.add_constraint(pub_input_flg.clone() * (pub_input_flg - E::F::one()));
        let [pub_output_flg] = program_trace_eval!(trace_eval, ProgramColumn::PublicOutputFlag);
        eval.add_constraint(pub_output_flg.clone() * (pub_output_flg - E::F::one()));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};

    use crate::trace::PreprocessedTraces;
    use crate::traits::MachineChip;

    use nexus_vm::emulator::HarvardEmulator;
    use nexus_vm::WORD_SIZE;
    use stwo_prover::constraint_framework::TraceLocationAllocator;

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<RangeBoolChip>;

    #[test]
    fn test_range_bool_chip_success() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_trace = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace, &HarvardEmulator::default(), []);

        for row_idx in 0..traces.num_rows() {
            let b = row_idx % 2 == 0;
            for col in CHECKED_SINGLE.into_iter() {
                traces.fill_columns(row_idx, b, col);
            }
            for word in CHECKED_WORD.into_iter() {
                let b_word = [b; WORD_SIZE];
                traces.fill_columns(row_idx, b_word, word);
            }

            RangeBoolChip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut program_trace,
                &mut side_note,
            );
        }
        assert_chip::<RangeBoolChip>(traces, None);
    }

    #[test]
    #[should_panic]
    fn range_bool_chip_fail_out_of_range() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_trace = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace, &HarvardEmulator::default(), []);
        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 2 == 0) as u8 + 1; // sometimes out of range
            for col in CHECKED_SINGLE.into_iter() {
                traces.fill_columns(row_idx, b, col);
            }
            for word in CHECKED_WORD.into_iter() {
                let b_word = [b; WORD_SIZE];
                traces.fill_columns(row_idx, b_word, word);
            }

            RangeBoolChip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut program_trace,
                &mut side_note,
            );
        }
        let CommittedTraces {
            mut commitment_scheme,
            mut prover_channel,
            lookup_elements,
            preprocessed_trace: _,
            interaction_trace: _,
            program_trace: _,
        } = commit_traces::<RangeBoolChip>(config, &twiddles, &traces.finalize(), None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<RangeBoolChip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
