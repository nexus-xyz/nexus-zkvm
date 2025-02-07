// This file contains range-checking values for 0..=31.

use stwo_prover::constraint_framework::{logup::LogupTraceGenerator, Relation, RelationEntry};

use num_traits::{One, Zero};
use stwo_prover::core::{
    backend::simd::m31::LOG_N_LANES,
    fields::{m31::BaseField, qm31::SecureField},
};

use crate::{
    column::{
        Column::{self, Multiplicity32, OpA, OpB, Reg1Address, Reg2Address, Reg3Address},
        PreprocessedColumn::{self, Range32},
    },
    components::AllLookupElements,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
};

/// A Chip for range-checking values for 0..=31
///
/// Range32Chip needs to be located at the end of the chip composition together with the other range check chips
pub struct Range32Chip;

const LOOKUP_TUPLE_SIZE: usize = 1;
stwo_prover::relation!(Range32LookupElements, LOOKUP_TUPLE_SIZE);

const CHECKED: [Column; 5] = [OpA, OpB, Reg1Address, Reg2Address, Reg3Address];

impl MachineChip for Range32Chip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    ) {
        all_elements.insert(Range32LookupElements::draw(channel));
    }

    /// Increments Multiplicity32 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        for col in CHECKED.into_iter() {
            let [val] = traces.column(row_idx, col);
            fill_main_elm(val, traces);
        }
    }
    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &Range32LookupElements = lookup_element.as_ref();

        // Add checked occurrences to logup sum.
        // TODO: range-check other byte-ranged columns.
        for col in CHECKED.iter() {
            let [value_basecolumn]: [_; 1] = original_traces.get_base_column(*col);
            let log_size = original_traces.log_size();
            // TODO: we can deal with two limbs at a time.
            let mut logup_col_gen = logup_trace_gen.new_col();
            // vec_row is row_idx divided by 16. Because SIMD.
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let checked_tuple = vec![value_basecolumn.data[vec_row]];
                let denom = lookup_element.combine(&checked_tuple);
                logup_col_gen.write_frac(vec_row, SecureField::one().into(), denom);
            }
            logup_col_gen.finalize_col();
        }
        // Subtract looked up multiplicites from logup sum.
        let range_basecolumn: [_; Range32.size()] =
            preprocessed_traces.get_preprocessed_base_column(Range32);
        let multiplicity_basecolumn: [_; Multiplicity32.size()] =
            original_traces.get_base_column(Multiplicity32);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let reference_tuple = vec![range_basecolumn[0].data[vec_row]];
            let denom = lookup_element.combine(&reference_tuple);
            let numerator = multiplicity_basecolumn[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
    ) {
        let lookup_elements: &Range32LookupElements = lookup_elements.as_ref();

        // Add checked occurrences to logup sum.
        for col in CHECKED.iter() {
            // not using trace_eval! macro because it doesn't accept *col as an argument.
            let [value] = trace_eval.column_eval(*col);

            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                SecureField::one().into(),
                &[value],
            ));
        }
        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range32);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity32);
        let numerator: E::EF = (-multiplicity.clone()).into();

        eval.add_to_relation(RelationEntry::new(lookup_elements, numerator, &[range]));
    }
}

fn fill_main_elm(col: BaseField, traces: &mut TracesBuilder) {
    let checked = col.0;
    #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
    assert!(checked < 32, "value is out of range {}", checked);
    let multiplicity_col: [&mut BaseField; 1] = traces.column_mut(checked as usize, Multiplicity32);
    *multiplicity_col[0] += BaseField::one();
    // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    assert_ne!(*multiplicity_col[0], BaseField::zero());
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::preprocessed::PreprocessedBuilder;
    use crate::trace::program_trace::ProgramTracesBuilder;
    use crate::traits::MachineChip;

    use nexus_vm::emulator::{Emulator, HarvardEmulator};

    #[test]
    fn test_range32_chip_success() {
        const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default().finalize());

        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 32) as u8;

            for col in CHECKED.iter() {
                traces.fill_columns(row_idx, b, *col);
            }

            Range32Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
            );
        }
        assert_chip::<Range32Chip>(traces, None);
    }

    #[test]
    fn test_range32_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default().finalize());
        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 32) as u8 + 1; // sometimes out of range
            traces.fill_columns(row_idx, b, Column::OpB);

            Range32Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
            );
        }
        let CommittedTraces { claimed_sum, .. } =
            commit_traces::<Range32Chip>(config, &twiddles, &traces.finalize(), None);

        assert_ne!(claimed_sum, SecureField::zero());
    }
}
