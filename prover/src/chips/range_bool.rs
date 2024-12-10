// This file contains range-checking for columns containing only {0, 1}

use stwo_prover::constraint_framework::logup::LookupElements;

use num_traits::One;

use crate::{
    column::Column::{
        self, BorrowFlag, CH1Minus, CH2Minus, CH3Minus, CarryFlag, ImmB, ImmC, IsAdd, IsAnd,
        IsBltu, IsOr, IsPadding, IsSlt, IsSltu, IsSub, IsXor, PrgMemoryFlag, Ram1Accessed,
        Ram2Accessed, Ram3Accessed, Ram4Accessed, Reg1Accessed, Reg2Accessed, Reg3Accessed, SgnB,
        SgnC,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{eval::TraceEval, sidenote::SideNote, ProgramStep, Traces},
    traits::MachineChip,
    WORD_SIZE,
};

/// A Chip for range-checking values for {0, 1}
///
/// RangeBoolChip can be located anywhere in the chip composition.

pub struct RangeBoolChip;

const CHECKED_SINGLE: [Column; 21] = [
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
    IsPadding,
    SgnB,
    SgnC,
    Reg1Accessed,
    Reg2Accessed,
    Reg3Accessed,
    PrgMemoryFlag,
    Ram1Accessed,
    Ram2Accessed,
    Ram3Accessed,
    Ram4Accessed,
];
const CHECKED_WORD: [Column; 5] = [CarryFlag, BorrowFlag, CH1Minus, CH2Minus, CH3Minus];

impl MachineChip for RangeBoolChip {
    fn fill_main_trace(
        _traces: &mut Traces,
        _row_idx: usize,
        _step: &ProgramStep,
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
            let ([col], _) = trace_eval.column_eval(col);
            eval.add_constraint(col.clone() * (col - E::F::one()));
        }
        for col_word in CHECKED_WORD.into_iter() {
            let (col_word, _) = trace_eval.column_eval::<WORD_SIZE>(col_word);
            for limb in col_word.into_iter() {
                eval.add_constraint(limb.clone() * (limb - E::F::one()));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
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
        let mut side_note = SideNote::default();

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
                &ProgramStep::default(),
                &mut side_note,
            );
        }
        let preprocessed_bool_rows = PreprocessedTraces::empty(LOG_SIZE);
        assert_chip::<RangeBoolChip>(traces, Some(preprocessed_bool_rows));
    }

    #[test]
    #[should_panic]
    fn range_bool_chip_fail_out_of_range() {
        const LOG_SIZE: u32 = 10;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = Traces::new(LOG_SIZE);
        let mut side_note = SideNote::default();
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
                &ProgramStep::default(),
                &mut side_note,
            );
        }
        let CommittedTraces {
            mut commitment_scheme,
            mut prover_channel,
            lookup_elements,
            preprocessed_trace: _,
            interaction_trace: _,
        } = commit_traces::<RangeBoolChip>(config, &twiddles, &traces, None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<RangeBoolChip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
