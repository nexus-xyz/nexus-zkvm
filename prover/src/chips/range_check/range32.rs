// This file contains range-checking values for 0..=31.

use stwo_prover::constraint_framework::logup::{LogupTraceGenerator, LookupElements};

use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{logup::LogupAtRow, INTERACTION_TRACE_IDX},
    core::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        lookups::utils::Fraction,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{
    column::{
        Column::{self, Multiplicity32, OpA, OpB, Reg1Address, Reg2Address, Reg3Address},
        PreprocessedColumn::{self, IsFirst, Range32},
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::{ProgramTraces, ProgramTracesBuilder},
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
};

/// A Chip for range-checking values for 0..=31
///
/// Range32Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range32Chip;

const CHECKED: [Column; 5] = [OpA, OpB, Reg1Address, Reg2Address, Reg3Address];

impl MachineChip for Range32Chip {
    /// Increments Multiplicity32 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
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
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &LookupElements<12>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        // Add checked occurrences to logup sum.
        // TODO: range-check other byte-ranged columns.
        for col in CHECKED.iter() {
            let [value_basecolumn]: [_; 1] = original_traces.get_base_column(*col);
            let log_size = original_traces.log_size();
            let logup_trace_gen: &mut LogupTraceGenerator = &mut logup_trace_gen;
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

        let (ret, _total_logup_sum) = logup_trace_gen.finalize_last();
        #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
        assert_eq!(_total_logup_sum, SecureField::zero());
        ret
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first] = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum.
        for col in CHECKED.iter() {
            // not using trace_eval! macro because it doesn't accept *col as an argument.
            let [value] = trace_eval.column_eval(*col);
            let denom: E::EF = lookup_elements.combine(&[value.clone()]);
            logup.write_frac(eval, Fraction::new(SecureField::one().into(), denom));
        }
        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range32);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity32);
        let denom: E::EF = lookup_elements.combine(&[range.clone()]);
        let numerator: E::EF = (-multiplicity.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
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

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::preprocessed::PreprocessedBuilder;
    use crate::traits::MachineChip;

    use nexus_vm::emulator::HarvardEmulator;
    use stwo_prover::constraint_framework::TraceLocationAllocator;

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<Range32Chip>;

    #[test]
    fn test_range32_chip_success() {
        const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default(), []);

        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 32) as u8;

            for col in CHECKED.iter() {
                traces.fill_columns(row_idx, b, *col);
            }

            Range32Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut program_traces,
                &mut side_note,
            );
        }
        assert_chip::<Range32Chip>(traces, None);
    }

    #[test]
    #[should_panic(expected = "ConstraintsNotSatisfied")]
    fn test_range32_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default(), []);
        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 32) as u8 + 1; // sometimes out of range
            traces.fill_columns(row_idx, b, Column::OpB);

            Range32Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut program_traces,
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
        } = commit_traces::<Range32Chip>(config, &twiddles, &traces.finalize(), None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<Range32Chip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
