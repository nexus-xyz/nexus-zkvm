// This file contains range-checking values for 0..=127.

// The target of the 0..127 rangecheck depends on the opcode.

use stwo_constraint_framework::{LogupTraceGenerator, Relation, RelationEntry};

use nexus_vm::WORD_SIZE;
use num_traits::Zero as _;
use stwo::{
    core::fields::m31::BaseField,
    prover::backend::simd::{
        column::BaseColumn,
        m31::{PackedBaseField, LOG_N_LANES},
    },
};

use crate::{
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        program_trace::ProgramTraces, sidenote::SideNote, FinalizedTraces, PreprocessedTraces,
        ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
};

use crate::column::Column::{self, Helper2, Helper3, IsBge, IsBlt, IsSlt};

/// A Chip for range-checking values for 0..=127
///
/// Range128Chip needs to be located at the end of the chip composition together with the other range check chips
pub struct Range128Chip;

const LOOKUP_TUPLE_SIZE: usize = 1;
stwo_constraint_framework::relation!(Range128LookupElements, LOOKUP_TUPLE_SIZE);

impl MachineChip for Range128Chip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo::core::channel::Channel,
        _config: &ExtensionsConfig,
    ) {
        all_elements.insert(Range128LookupElements::draw(channel));
    }

    /// Increments Multiplicity256 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let [is_slt] = traces.column(row_idx, IsSlt);
        let [is_bge] = traces.column(row_idx, IsBge);
        let [is_blt] = traces.column(row_idx, IsBlt);
        let last_limb_checked = [Helper2, Helper3];
        for col in last_limb_checked.into_iter() {
            let word: [_; WORD_SIZE] = traces.column(row_idx, col);
            let last_limb = word[3];
            fill_main_col(last_limb, is_slt + is_bge + is_blt, side_note);
        }
        let [is_jalr] = traces.column(row_idx, Column::IsJalr);
        let [qt_aux] = traces.column(row_idx, Column::QtAux);
        fill_main_col(qt_aux, is_jalr, side_note);
        // Check the first limb in Helper2 when SRA chip is used
        let [is_sra] = traces.column(row_idx, Column::IsSra);
        let [h2_sra, _, _, _] = traces.column(row_idx, Helper2);
        fill_main_col(h2_sra, is_sra, side_note);
        let [is_lh] = traces.column(row_idx, Column::IsLh);
        fill_main_col(qt_aux, is_lh, side_note);
        let [is_lb] = traces.column(row_idx, Column::IsLb);
        fill_main_col(qt_aux, is_lb, side_note);
    }
    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        _preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &Range128LookupElements = lookup_element.as_ref();
        // Add checked occurrences to logup sum.
        // TODO: range-check other byte-ranged columns.
        let [is_slt]: [_; 1] = original_traces.get_base_column(IsSlt);
        let [is_bge]: [_; 1] = original_traces.get_base_column(IsBge);
        let [is_blt]: [_; 1] = original_traces.get_base_column(IsBlt);
        for col in [Helper2, Helper3].into_iter() {
            let helper: [_; WORD_SIZE] = original_traces.get_base_column(col);
            check_col(
                helper[3],
                &[is_slt, is_bge, is_blt],
                original_traces.log_size(),
                logup_trace_gen,
                lookup_element,
            );
        }
        let [is_jalr] = original_traces.get_base_column(Column::IsJalr);
        let [qt_aux] = original_traces.get_base_column(Column::QtAux);
        check_col(
            qt_aux,
            &[is_jalr],
            original_traces.log_size(),
            logup_trace_gen,
            lookup_element,
        );
        let [is_sra] = original_traces.get_base_column(Column::IsSra);
        let [h2_sra, _, _, _] = original_traces.get_base_column(Helper2);
        check_col(
            h2_sra,
            &[is_sra],
            original_traces.log_size(),
            logup_trace_gen,
            lookup_element,
        );
        let [is_lh] = original_traces.get_base_column(Column::IsLh);
        let [is_lb] = original_traces.get_base_column(Column::IsLb);
        check_col(
            qt_aux,
            &[is_lh, is_lb],
            original_traces.log_size(),
            logup_trace_gen,
            lookup_element,
        );
    }

    fn add_constraints<E: stwo_constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let lookup_elements: &Range128LookupElements = lookup_elements.as_ref();

        // Add checked occurrences to logup sum.
        // not using trace_eval! macro because it doesn't accept *col as an argument.
        let [is_slt] = trace_eval.column_eval(IsSlt);
        let [is_bge] = trace_eval.column_eval(IsBge);
        let [is_blt] = trace_eval.column_eval(IsBlt);

        let numerator = is_slt.clone() + is_bge.clone() + is_blt.clone();
        for col in [Helper2, Helper3].into_iter() {
            let value = trace_eval.column_eval::<WORD_SIZE>(col);

            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                numerator.clone().into(),
                &[value[3].clone()],
            ));
        }
        let [is_jalr] = trace_eval.column_eval(Column::IsJalr);
        let [qt_aux] = trace_eval.column_eval(Column::QtAux);
        let numerator = is_jalr.clone();

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &[qt_aux.clone()],
        ));

        let [is_sra] = trace_eval.column_eval(Column::IsSra);
        let [h2_sra, _, _, _] = trace_eval.column_eval::<WORD_SIZE>(Helper2);
        let numerator = is_sra.clone();

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &[h2_sra],
        ));

        let [is_lh] = trace_eval.column_eval(Column::IsLh);
        let [is_lb] = trace_eval.column_eval(Column::IsLb);
        let numerator = is_lh.clone() + is_lb.clone();

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &[qt_aux],
        ));
    }
}

fn fill_main_col(value_col: BaseField, selector_col: BaseField, side_note: &mut SideNote) {
    if selector_col.is_zero() {
        return;
    }
    let checked = value_col.0;
    #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
    assert!(checked < 128, "value is out of range {checked}");
    side_note.range128.multiplicity[checked as usize] += 1;
}

fn check_col(
    base_column: &BaseColumn,
    selectors: &[&BaseColumn],
    log_size: u32,
    logup_trace_gen: &mut LogupTraceGenerator,
    lookup_element: &Range128LookupElements,
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

    use crate::extensions::ExtensionComponent;
    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::program_trace::{ProgramTraceRef, ProgramTracesBuilder};
    use crate::trace::{preprocessed::PreprocessedBuilder, Word};
    use crate::traits::MachineChip;

    use nexus_vm::emulator::{Emulator, HarvardEmulator, ProgramInfo};

    use stwo::core::fields::qm31::SecureField;

    #[test]
    fn test_range128_chip_success() {
        const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_trace = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace, &HarvardEmulator::default().finalize());
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
                &ExtensionsConfig::default(),
            );
        }
        assert_chip::<Range128Chip>(traces, None);
    }

    #[test]
    fn test_range128_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_info = ProgramInfo::dummy();
        let program_trace_ref = ProgramTraceRef {
            program_memory: &program_info,
            init_memory: Default::default(),
            exit_code: Default::default(),
            public_output: Default::default(),
        };
        let program_traces = ProgramTracesBuilder::new(LOG_SIZE, program_trace_ref);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default().finalize());
        // Write in-range values to ValueA columns.
        for row_idx in 0..(1 << LOG_SIZE) {
            let buf: Word = array::from_fn(|i| (row_idx + i) as u8 % 128);
            traces.fill_columns(row_idx, buf, Helper3);
            traces.fill_columns(row_idx, true, IsSlt);

            Range128Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        // modify looked up value
        *traces.column_mut::<{ Helper2.size() }>(11, Helper2)[3] = BaseField::from(128u32);

        let CommittedTraces {
            claimed_sum,
            lookup_elements,
            ..
        } = commit_traces::<Range128Chip>(config, &twiddles, &traces.finalize(), None);

        // verify that logup sums don't match
        let ext = ExtensionComponent::multiplicity128();
        let component_trace = ext.generate_component_trace(
            128u32.trailing_zeros(),
            program_trace_ref,
            &mut side_note,
        );
        let (_, claimed_sum_2) =
            ext.generate_interaction_trace(component_trace, &side_note, &lookup_elements);
        assert_ne!(claimed_sum + claimed_sum_2, SecureField::zero());
    }
}
