// This file contains range-checking values for 0..=15.

use nexus_vm::riscv::InstructionType;
use stwo_prover::{
    constraint_framework::logup::{LogupTraceGenerator, LookupElements},
    core::fields::m31,
};

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
    column::{
        Column::{self, Multiplicity16, OpA14, OpB14, OpC03},
        PreprocessedColumn::{self, IsFirst, Range16},
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

/// A Chip for range-checking values for 0..=15
///
/// Range16Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range16Chip;

const TYPE_R_CHECKED: [Column; 3] = [OpC03, OpA14, OpB14];

impl MachineChip for Range16Chip {
    /// Increments Multiplicity16 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        step: &Option<ProgramStep>,
        _program_traces: &ProgramTraces,
        side_note: &mut SideNote,
    ) {
        let step_is_type_r = step
            .as_ref()
            .is_some_and(|step| step.step.instruction.ins_type == InstructionType::RType);
        debug_assert_eq!(
            step_is_type_r,
            {
                let [is_type_r] =
                    virtual_column::IsTypeR::read_from_traces_builder(traces, row_idx);
                !is_type_r.is_zero()
            },
            "ProgramStep and the TraceBuilder seem to disagree whether this row is type R",
        );
        if step_is_type_r {
            for col in TYPE_R_CHECKED.into_iter() {
                let [val] = traces.column(row_idx, col);
                fill_main_elm(val, traces, side_note);
            }
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
        for col in TYPE_R_CHECKED.iter() {
            let [value_basecolumn]: [&BaseColumn; 1] = original_traces.get_base_column(*col);
            let log_size = original_traces.log_size();
            let logup_trace_gen: &mut LogupTraceGenerator = &mut logup_trace_gen;
            // TODO: we can deal with two limbs at a time.
            let mut logup_col_gen = logup_trace_gen.new_col();
            // vec_row is row_idx divided by 16. Because SIMD.
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let checked_tuple = vec![value_basecolumn.data[vec_row]];
                let denom = lookup_element.combine(&checked_tuple);
                let [type_r] =
                    virtual_column::IsTypeR::read_from_finalized_traces(original_traces, vec_row);
                logup_col_gen.write_frac(vec_row, type_r.into(), denom);
            }
            logup_col_gen.finalize_col();
        }
        // Subtract looked up multiplicites from logup sum.
        let range_basecolumn: [&BaseColumn; Range16.size()] =
            preprocessed_traces.get_preprocessed_base_column(Range16);
        let multiplicity_basecolumn: [&BaseColumn; Multiplicity16.size()] =
            original_traces.get_base_column(Multiplicity16);
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
        for col in TYPE_R_CHECKED.iter() {
            // not using trace_eval! macro because it doesn't accept *col as an argument.
            let [value] = trace_eval.column_eval(*col);
            let denom: E::EF = lookup_elements.combine(&[value.clone()]);
            let [numerator] = virtual_column::IsTypeR::eval(trace_eval);
            logup.write_frac(eval, Fraction::new(numerator.into(), denom));
        }
        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range16);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity16);
        let denom: E::EF = lookup_elements.combine(&[range.clone()]);
        let numerator: E::EF = (-multiplicity.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
    }
}

fn fill_main_elm(col: BaseField, traces: &mut TracesBuilder, side_note: &mut SideNote) {
    let checked = col.0;
    #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
    assert!(checked < 16, "value is out of range {}", checked);
    let multiplicity_col: [&mut BaseField; 1] = traces.column_mut(checked as usize, Multiplicity16);
    *multiplicity_col[0] += BaseField::one();
    // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    assert_ne!(*multiplicity_col[0], BaseField::zero());
    // Detect global overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    side_note.range16.global_multiplicity += 1;
    assert_ne!(side_note.range16.global_multiplicity, m31::P);
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::preprocessed::PreprocessedBuilder;
    use crate::traits::MachineChip;

    use stwo_prover::constraint_framework::TraceLocationAllocator;

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<Range16Chip>;

    #[test]
    fn test_range16_chip_success() {
        const LOG_SIZE: u32 = 10; // Traces::MIN_LOG_SIZE makes the test too slow.
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTraces::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces);

        let mut program_step = ProgramStep::default();
        program_step.step.instruction.ins_type = InstructionType::RType;

        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 16) as u8;

            for col in TYPE_R_CHECKED.iter() {
                traces.fill_columns(row_idx, b, *col);
            }
            traces.fill_columns(row_idx, true, Column::IsAdd);

            Range16Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(program_step.clone()),
                &program_traces,
                &mut side_note,
            );
        }
        let mut preprocessed_16_rows = PreprocessedBuilder::empty(LOG_SIZE);
        preprocessed_16_rows.fill_is_first();
        preprocessed_16_rows.fill_range16();
        assert_chip::<Range16Chip>(traces, Some(preprocessed_16_rows), None);
    }

    #[test]
    #[should_panic(expected = "ConstraintsNotSatisfied")]
    fn test_range16_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTraces::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces);
        let mut program_step = ProgramStep::default();
        program_step.step.instruction.ins_type = InstructionType::RType;

        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 16) as u8 + 1; // sometimes out of range
            traces.fill_columns(row_idx, b, Column::OpB14);
            traces.fill_columns(row_idx, true, Column::IsAdd);

            Range16Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(program_step.clone()),
                &program_traces,
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
        } = commit_traces::<Range16Chip>(config, &twiddles, &traces.finalize(), None, None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<Range16Chip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
