// This file contains range-checking values for 0..=127.

// The target of the 0..127 rangecheck depends on the opcode.

use stwo_prover::{
    constraint_framework::logup::{LogupTraceGenerator, LookupElements},
    core::{backend::simd::m31::PackedBaseField, fields::m31},
};

use nexus_vm::WORD_SIZE;
use num_traits::{One as _, Zero as _};
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
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        PreprocessedTraces, ProgramStep, Traces,
    },
    traits::MachineChip,
};

use crate::column::Column::{self, Helper2, Helper3, IsBge, IsBlt, IsSlt, Multiplicity128};
use crate::column::PreprocessedColumn::{self, IsFirst, Range128};

/// A Chip for range-checking values for 0..=127
///
/// Range128Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range128Chip;

impl MachineChip for Range128Chip {
    /// Increments Multiplicity256 for every number checked
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        side_note: &mut SideNote,
    ) {
        let [is_slt] = traces.column(row_idx, IsSlt);
        let [is_bge] = traces.column(row_idx, IsBge);
        let [is_blt] = traces.column(row_idx, IsBlt);
        let last_limb_checked = [Helper2, Helper3];
        for col in last_limb_checked.into_iter() {
            let word: [_; WORD_SIZE] = traces.column(row_idx, col);
            let last_limb = word[3];
            fill_main_col(last_limb, is_slt + is_bge + is_blt, traces, side_note);
        }
    }
    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        original_traces: &Traces,
        preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &LookupElements<12>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        // Add checked occurrences to logup sum.
        // TODO: range-check other byte-ranged columns.
        let [is_slt]: [BaseColumn; 1] = original_traces.get_base_column(IsSlt);
        let [is_bge]: [BaseColumn; 1] = original_traces.get_base_column(IsBge);
        let [is_blt]: [BaseColumn; 1] = original_traces.get_base_column(IsBlt);
        for col in [Helper2, Helper3].into_iter() {
            let helper: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(col);
            check_col(
                &helper[3],
                &[&is_slt, &is_bge, &is_blt],
                original_traces.log_size(),
                &mut logup_trace_gen,
                lookup_element,
            );
        }
        // Subtract looked up multiplicites from logup sum.
        let range_basecolumn: [BaseColumn; Range128.size()] =
            preprocessed_traces.get_preprocessed_base_column(Range128);
        let multiplicity_basecolumn: [BaseColumn; Multiplicity128.size()] =
            original_traces.get_base_column(Multiplicity128);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let reference_tuple = vec![range_basecolumn[0].data[vec_row]];
            let denom = lookup_element.combine(&reference_tuple);
            let numerator = multiplicity_basecolumn[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();

        let (ret, _total_logup_sum) = logup_trace_gen.finalize_last();
        #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
        assert_eq!(_total_logup_sum, SecureField::zero());
        ret
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first] = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum.
        // not using trace_eval! macro because it doesn't accept *col as an argument.
        let [is_slt] = trace_eval.column_eval(IsSlt);
        let [is_bge] = trace_eval.column_eval(IsBge);
        let [is_blt] = trace_eval.column_eval(IsBlt);
        for col in [Helper2, Helper3].into_iter() {
            let value = trace_eval.column_eval::<WORD_SIZE>(col);
            let denom: E::EF = lookup_elements.combine(&[value[3].clone()]);
            let numerator = is_slt.clone() + is_bge.clone() + is_blt.clone();
            logup.write_frac(eval, Fraction::new(numerator.into(), denom));
        }
        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range128);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity128);
        let denom: E::EF = lookup_elements.combine(&[range.clone()]);
        let numerator: E::EF = (-multiplicity.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
    }
}

fn fill_main_col(
    value_col: BaseField,
    selector_col: BaseField,
    traces: &mut Traces,
    side_note: &mut SideNote,
) {
    if selector_col.is_zero() {
        return;
    }
    let checked = value_col.0;
    #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
    assert!(checked < 128, "value is out of range {}", checked);
    let multiplicity_col: [&mut BaseField; 1] =
        traces.column_mut(checked as usize, Multiplicity128);
    *multiplicity_col[0] += BaseField::one();
    // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    assert_ne!(*multiplicity_col[0], BaseField::zero());
    // Detect global overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    side_note.range128.global_multiplicity += 1;
    assert_ne!(side_note.range128.global_multiplicity, m31::P);
}

fn check_col(
    base_column: &BaseColumn,
    selectors: &[&BaseColumn],
    log_size: u32,
    logup_trace_gen: &mut LogupTraceGenerator,
    lookup_element: &LookupElements<12>,
) {
    let mut logup_col_gen = logup_trace_gen.new_col();
    // vec_row is row_idx divided by 16. Because SIMD.
    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let checked_tuple = vec![base_column.data[vec_row]];
        let denom = lookup_element.combine(&checked_tuple);
        let mut numerator = PackedBaseField::zero();
        for selector in selectors.iter() {
            let numerator_selector = selector.data[vec_row];
            numerator += numerator_selector;
        }
        logup_col_gen.write_frac(vec_row, numerator.into(), denom);
    }
    logup_col_gen.finalize_col();
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

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<Range128Chip>;

    #[test]
    fn test_range128_chip_success() {
        const LOG_SIZE: u32 = 10; // Traces::MIN_LOG_SIZE makes the test too slow.
        let mut traces = Traces::new(LOG_SIZE);
        let program_trace = ProgramTraces::new(LOG_SIZE, []);
        let mut side_note = SideNote::new(&program_trace);
        // Write in-range values to ValueA columns.
        for row_idx in 0..(1 << LOG_SIZE) {
            let buf: Word = array::from_fn(|i| (row_idx + i) as u8 % 128);

            // TODO: implement and use ToBaseFields for Word, in order to avoid copying here
            if row_idx % 2 == 0 {
                // IsSlt row, filling in-range values
                traces.fill_columns(row_idx, true, IsSlt);
                traces.fill_columns(row_idx, buf, Helper2);
                traces.fill_columns(row_idx, buf, Helper3);
            } else {
                // not IsSlt row, filling out-of-range values sometimes
                traces.fill_columns(row_idx, true, IsSlt);
                traces.fill_columns(row_idx, row_idx as u32, Helper2);
                traces.fill_columns(row_idx, row_idx as u32 + 100, Helper3);
            }

            Range128Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
            );
        }
        let mut preprocessed_128_rows = PreprocessedTraces::empty(LOG_SIZE);
        preprocessed_128_rows.fill_is_first();
        preprocessed_128_rows.fill_range128();
        assert_chip::<Range128Chip>(traces, Some(preprocessed_128_rows), None);
    }

    #[test]
    #[should_panic(expected = "ConstraintsNotSatisfied")]
    fn test_range128_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = Traces::new(LOG_SIZE);
        let program_traces = ProgramTraces::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces);
        // Write in-range values to ValueA columns.
        for row_idx in 0..(1 << LOG_SIZE) {
            let buf: Word = array::from_fn(
                |i| (row_idx + i) as u8 % 128 + 1, /* sometimes out of range */
            );
            traces.fill_columns(row_idx, buf, Helper3);
            traces.fill_columns(row_idx, true, IsSlt);

            Range128Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
            );
        }
        let CommittedTraces {
            mut commitment_scheme,
            mut prover_channel,
            lookup_elements,
            preprocessed_trace: _,
            program_trace: _,
            interaction_trace: _,
        } = commit_traces::<Range128Chip>(config, &twiddles, &traces, None, None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<Range128Chip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
