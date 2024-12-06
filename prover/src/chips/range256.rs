// This file contains range-checking values for 0..=255.

use stwo_prover::{
    constraint_framework::logup::{LogupTraceGenerator, LookupElements},
    core::fields::m31,
};

use nexus_vm::WORD_SIZE;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{logup::LogupAtRow, INTERACTION_TRACE_IDX},
    core::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        lookups::utils::Fraction,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{
    column::Column::{
        self, CReg1TsPrev, CReg2TsPrev, CReg3TsPrev, FinalPrgMemoryCtr, FinalRegTs, FinalRegValue,
        Helper1, InstrVal, Multiplicity256, Pc, PrevCtr, PrgMemoryPc, PrgMemoryWord, ProgCtrCur,
        ProgCtrPrev, Reg1TsPrev, Reg2TsPrev, Reg3TsPrev, ValueA, ValueB, ValueC,
    },
    column::PreprocessedColumn::{self, IsFirst, Range256},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        sidenote::SideNote,
        PreprocessedTraces, ProgramStep, Traces,
    },
    traits::MachineChip,
};

/// A Chip for range-checking values for 0..=255
///
/// Range256Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range256Chip;

impl Range256Chip {
    const CHECKED: [Column; 20] = [
        Pc,
        InstrVal,
        PrevCtr,
        ValueA,
        ValueB,
        ValueC,
        Reg1TsPrev,
        Reg2TsPrev,
        Reg3TsPrev,
        Helper1,
        ProgCtrCur,
        ProgCtrPrev,
        FinalRegTs,
        FinalRegValue,
        PrgMemoryPc,
        PrgMemoryWord,
        FinalPrgMemoryCtr,
        CReg1TsPrev,
        CReg2TsPrev,
        CReg3TsPrev,
    ];
}

impl MachineChip for Range256Chip {
    /// Increments Multiplicity256 for every number checked
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        _step: &ProgramStep,
        side_note: &mut SideNote,
    ) {
        for col in Self::CHECKED.iter() {
            // not using trace_column! because it doesn't accept *col as an argument.
            let value_col: [BaseField; WORD_SIZE] = traces.column(row_idx, *col);
            fill_main_word(value_col, traces, side_note);
        }
        // TODO: check the other columns, too.
    }
    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        original_traces: &Traces,
        preprocessed_traces: &PreprocessedTraces,
        lookup_element: &LookupElements<12>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        // Add checked occurrences to logup sum.
        // TODO: range-check other byte-ranged columns.
        for col in Self::CHECKED.iter() {
            let value_basecolumn: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(*col);
            check_word_limbs(
                value_basecolumn,
                original_traces.log_size(),
                &mut logup_trace_gen,
                lookup_element,
            );
        }
        // Subtract looked up multiplicites from logup sum.
        let range_basecolumn: [BaseColumn; Range256.size()] =
            preprocessed_traces.get_preprocessed_base_column(Range256);
        let multiplicity_basecolumn: [BaseColumn; Multiplicity256.size()] =
            original_traces.get_base_column(Multiplicity256);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let reference_tuple = vec![range_basecolumn[0].data[vec_row]];
            let denom = lookup_element.combine(&reference_tuple);
            let numerator = multiplicity_basecolumn[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();

        let (ret, _total_logup_sum) = logup_trace_gen.finalize_last();
        #[cfg(not(test))] // tests need to be able to go past this assertion and break the constraints
        assert_eq!(_total_logup_sum, SecureField::zero());
        ret
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let ([is_first], _) = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum.
        for col in Self::CHECKED.iter() {
            // not using trace_eval! macro because it doesn't accept *col as an argument.
            let (value, _) = trace_eval.column_eval::<WORD_SIZE>(*col);
            for limb in value.iter().take(WORD_SIZE) {
                let denom: E::EF = lookup_elements.combine(&[limb.clone()]);
                logup.write_frac(eval, Fraction::new(SecureField::one().into(), denom));
            }
        }
        // Subtract looked up multiplicites from logup sum.
        let ([range], _) = preprocessed_trace_eval!(trace_eval, Range256);
        let ([multiplicity], _) = trace_eval!(trace_eval, Multiplicity256);
        let denom: E::EF = lookup_elements.combine(&[range.clone()]);
        let numerator: E::EF = (-multiplicity.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
    }
}

fn fill_main_word(
    value_col: [BaseField; WORD_SIZE],
    traces: &mut Traces,
    side_note: &mut SideNote,
) {
    for (_limb_index, limb) in value_col.iter().enumerate().take(WORD_SIZE) {
        let checked = limb.0;
        #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
        assert!(checked < 256, "value[{}] is out of range", _limb_index);
        let multiplicity_col: [&mut BaseField; 1] =
            traces.column_mut(checked as usize, Multiplicity256);
        *multiplicity_col[0] += BaseField::one();
        // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
        assert_ne!(*multiplicity_col[0], BaseField::zero());
        // Detect global overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
        side_note.range256.global_multiplicity += 1;
        assert_ne!(side_note.range256.global_multiplicity, m31::P);
    }
}

fn check_word_limbs(
    basecolumn: [BaseColumn; WORD_SIZE],
    log_size: u32,
    logup_trace_gen: &mut LogupTraceGenerator,
    lookup_element: &LookupElements<12>,
) {
    // TODO: we can deal with two limbs at a time.
    for limb in basecolumn.iter().take(WORD_SIZE) {
        let mut logup_col_gen = logup_trace_gen.new_col();
        // vec_row is row_idx divided by 16. Because SIMD.
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let checked_tuple = vec![limb.data[vec_row]];
            let denom = lookup_element.combine(&checked_tuple);
            logup_col_gen.write_frac(vec_row, SecureField::one().into(), denom);
        }
        logup_col_gen.finalize_col();
    }
}

#[cfg(test)]
mod test {
    use std::array;

    use super::*;

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::Word;
    use crate::traits::MachineChip;

    use stwo_prover::constraint_framework::TraceLocationAllocator;

    use stwo_prover::core::fields::m31::BaseField;

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<Range256Chip>;

    #[test]
    fn test_range256_chip_success() {
        const LOG_SIZE: u32 = 10; // Traces::MIN_LOG_SIZE makes the test too slow.
        let mut traces = Traces::new(LOG_SIZE);
        let mut side_note = SideNote::default();
        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let buf: Word = array::from_fn(|i| (row_idx + i) as u8);

            traces.fill_columns_bytes(row_idx, &buf, ValueA);
            traces.fill_columns_bytes(row_idx, &buf, ValueB);
            traces.fill_columns_bytes(row_idx, &buf, ValueC);

            Range256Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &ProgramStep::default(),
                &mut side_note,
            );
        }
        let mut preprocessed_256_rows = PreprocessedTraces::empty(LOG_SIZE);
        preprocessed_256_rows.fill_is_first();
        preprocessed_256_rows.fill_range256();
        assert_chip::<Range256Chip>(traces, Some(preprocessed_256_rows));
    }

    #[test]
    #[should_panic(expected = "ConstraintsNotSatisfied")]
    fn test_range256_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = Traces::new(LOG_SIZE);
        let mut side_note = SideNote::default();
        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let buf: [BaseField; WORD_SIZE] = array::from_fn(|i| {
                // sometimes out of range
                let t = ((row_idx + i) as u8) as u32 + 1u32;
                BaseField::from(t)
            });
            traces.fill_columns_basefield(row_idx, &buf, ValueB);

            Range256Chip::fill_main_trace(
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
        } = commit_traces::<Range256Chip>(config, &twiddles, &traces, None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<Range256Chip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
