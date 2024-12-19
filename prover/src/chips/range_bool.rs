// This file contains range-checking for columns containing only {0, 1}

use stwo_prover::constraint_framework::logup::LookupElements;

use num_traits::One;

use crate::{
    column::Column::{
        self, BorrowFlag, CH1Minus, CH2Minus, CH3Minus, CarryFlag, ImmB, ImmC, IsAdd, IsAnd, IsBge,
        IsBgeu, IsBlt, IsBltu, IsJal, IsOr, IsPadding, IsSlt, IsSltu, IsSub, IsXor, LtFlag,
        Ram1Accessed, Ram2Accessed, Ram3Accessed, Ram4Accessed, Reg1Accessed, Reg2Accessed,
        Reg3Accessed, SgnA, SgnB, SgnC,
    },
    column::ProgramColumn,
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::program_trace_eval, eval::TraceEval, program_trace::ProgramTraces,
        sidenote::SideNote, ProgramStep, Traces,
    },
    traits::MachineChip,
    WORD_SIZE,
};

/// A Chip for range-checking values for {0, 1}
///
/// RangeBoolChip can be located anywhere in the chip composition.

pub struct RangeBoolChip;

const CHECKED_SINGLE: [Column; 26] = [
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
    IsPadding,
    LtFlag,
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
];
const CHECKED_WORD: [Column; 5] = [CarryFlag, BorrowFlag, CH1Minus, CH2Minus, CH3Minus];

// TODO: also range-check PrgMemoryFlag in program trace

impl MachineChip for RangeBoolChip {
    fn fill_main_trace(
        _traces: &mut Traces,
        _row_idx: usize,
        _step: &Option<ProgramStep>,
        _program_traces: &ProgramTraces,
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
        for col_word in CHECKED_WORD.into_iter() {
            let col_word = trace_eval.column_eval::<WORD_SIZE>(col_word);
            for limb in col_word.into_iter() {
                eval.add_constraint(limb.clone() * (limb - E::F::one()));
            }
        }
        let [prg_memory_flg] = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryFlag);
        eval.add_constraint(prg_memory_flg.clone() * (prg_memory_flg - E::F::one()));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::program_trace::ProgramTraces;
    use crate::trace::PreprocessedTraces;
    use crate::traits::MachineChip;

    use nexus_vm::WORD_SIZE;
    use stwo_prover::constraint_framework::TraceLocationAllocator;

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<RangeBoolChip>;

    #[test]
    fn test_range_bool_chip_success() {
        const LOG_SIZE: u32 = 10; // Traces::MIN_LOG_SIZE makes the test too slow.
        let mut traces = Traces::new(LOG_SIZE);
        let program_trace = ProgramTraces::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace);

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
                &program_trace,
                &mut side_note,
            );
        }
        let preprocessed_bool_rows = PreprocessedTraces::empty(LOG_SIZE);
        assert_chip::<RangeBoolChip>(traces, Some(preprocessed_bool_rows), None);
    }

    #[test]
    #[should_panic]
    fn range_bool_chip_fail_out_of_range() {
        const LOG_SIZE: u32 = 10;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = Traces::new(LOG_SIZE);
        let program_trace = ProgramTraces::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace);
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
                &program_trace,
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
        } = commit_traces::<RangeBoolChip>(config, &twiddles, &traces, None, None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<RangeBoolChip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
