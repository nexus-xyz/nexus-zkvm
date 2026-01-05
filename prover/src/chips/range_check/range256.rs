// This file contains range-checking values for 0..=255.

use stwo_constraint_framework::{LogupTraceGenerator, Relation, RelationEntry};

use nexus_vm::WORD_SIZE;
use num_traits::{One, Zero};
use stwo::{
    core::fields::{m31::BaseField, qm31::SecureField},
    prover::backend::simd::{column::BaseColumn, m31::LOG_N_LANES},
};

use crate::{
    column::Column::{
        self, CReg1TsPrev, CReg2TsPrev, CReg3TsPrev, FinalPrgMemoryCtr, Helper1, HelperT, HelperU,
        InstrVal, MulP1, MulP3Prime, MulP3PrimePrime, MulP5, OpC16_23, OpC24_31, Pc, PcNextAux,
        PrevCtr, ProgCtrCur, ProgCtrPrev, Qt, Quotient, Ram1TsPrev, Ram1TsPrevAux, Ram1ValCur,
        Ram1ValPrev, Ram2TsPrev, Ram2TsPrevAux, Ram2ValCur, Ram2ValPrev, Ram3TsPrev, Ram3TsPrevAux,
        Ram3ValCur, Ram3ValPrev, Ram4TsPrev, Ram4TsPrevAux, Ram4ValCur, Ram4ValPrev, RamBaseAddr,
        Reg1TsPrev, Reg2TsPrev, Reg3TsPrev, Rem, RemDiff, Remainder, ValueA, ValueAAbs,
        ValueAAbsHigh, ValueALow, ValueB, ValueBAbs, ValueC, ValueCAbs,
    },
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::TraceEval, program_trace::ProgramTraces, sidenote::SideNote, FinalizedTraces,
        PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

/// A Chip for range-checking values for 0..=255
///
/// Range256Chip needs to be located at the end of the chip composition together with the other range check chips
pub struct Range256Chip;

const LOOKUP_TUPLE_SIZE: usize = 1;
stwo_constraint_framework::relation!(Range256LookupElements, LOOKUP_TUPLE_SIZE);

impl Range256Chip {
    const CHECKED_WORDS: [Column; 38] = [
        Pc,
        PcNextAux,
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
        FinalPrgMemoryCtr,
        CReg1TsPrev,
        CReg2TsPrev,
        CReg3TsPrev,
        RamBaseAddr,
        Ram1TsPrev,
        Ram2TsPrev,
        Ram3TsPrev,
        Ram4TsPrev,
        Ram1TsPrevAux,
        Ram2TsPrevAux,
        Ram3TsPrevAux,
        Ram4TsPrevAux,
        Rem,
        Qt,
        RemDiff,
        HelperT,
        HelperU,
        Quotient,
        Remainder,
        ValueBAbs,
        ValueCAbs,
        ValueAAbs,
        ValueAAbsHigh,
        ValueALow,
    ];

    const CHECKED_BYTES: [Column; 8] = [
        Ram1ValCur,
        Ram2ValCur,
        Ram3ValCur,
        Ram4ValCur,
        Ram1ValPrev,
        Ram2ValPrev,
        Ram3ValPrev,
        Ram4ValPrev,
    ];

    const CHECKED_HALF_WORDS: [Column; 4] = [MulP1, MulP3Prime, MulP3PrimePrime, MulP5];

    const TYPE_U_CHECKED_BYTES: [Column; 2] = [OpC16_23, OpC24_31];
}

impl MachineChip for Range256Chip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo::core::channel::Channel,
        _config: &ExtensionsConfig,
    ) {
        all_elements.insert(Range256LookupElements::draw(channel));
    }

    /// Increments Multiplicity256 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        // This chip needs to wait till every other chip finishes writing bytes.
        // Since some other chips write bytes above the current row, we need to wait till other chips finished filling for the last row.
        if row_idx + 1 < traces.num_rows() {
            return;
        }
        for row_idx in 0..traces.num_rows() {
            for col in Self::CHECKED_WORDS.iter() {
                let value_col: [BaseField; WORD_SIZE] = traces.column(row_idx, *col);
                fill_main_cols(value_col, side_note);
            }
            for col in Self::CHECKED_HALF_WORDS.iter() {
                let value_col: [BaseField; 2] = traces.column::<2>(row_idx, *col);
                fill_main_cols(value_col, side_note);
            }
            for col in Self::CHECKED_BYTES.iter() {
                let value_col = traces.column::<1>(row_idx, *col);
                fill_main_cols(value_col, side_note);
            }
            let [type_u] = virtual_column::IsTypeU::read_from_traces_builder(traces, row_idx);
            if !type_u.is_zero() {
                for col in Self::TYPE_U_CHECKED_BYTES.iter() {
                    let value_col = traces.column::<1>(row_idx, *col);
                    fill_main_cols(value_col, side_note);
                }
            }
        }
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
        let lookup_element: &Range256LookupElements = lookup_element.as_ref();

        // Add checked occurrences to logup sum.
        for col in Self::CHECKED_WORDS.iter() {
            let value_basecolumn: [_; WORD_SIZE] = original_traces.get_base_column(*col);
            check_bytes(
                value_basecolumn,
                original_traces.log_size(),
                logup_trace_gen,
                lookup_element,
            );
        }

        for col in Self::CHECKED_HALF_WORDS.iter() {
            let value_basecolumn: [_; 2] = original_traces.get_base_column::<2>(*col);
            check_bytes(
                value_basecolumn,
                original_traces.log_size(),
                logup_trace_gen,
                lookup_element,
            );
        }

        for col in Self::CHECKED_BYTES.iter() {
            let value_basecolumn = original_traces.get_base_column::<1>(*col);
            check_bytes(
                value_basecolumn,
                original_traces.log_size(),
                logup_trace_gen,
                lookup_element,
            );
        }
        for col in Self::TYPE_U_CHECKED_BYTES.iter() {
            let value_basecolumn = original_traces.get_base_column::<1>(*col);
            {
                let log_size = original_traces.log_size();
                // TODO: we can deal with two limbs at a time.
                for limb in value_basecolumn.iter() {
                    let mut logup_col_gen = logup_trace_gen.new_col();
                    // vec_row is row_idx divided by 16. Because SIMD.
                    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                        let checked_tuple = vec![limb.data[vec_row]];
                        let denom = lookup_element.combine(&checked_tuple);
                        let [type_u] = virtual_column::IsTypeU::read_from_finalized_traces(
                            original_traces,
                            vec_row,
                        );
                        logup_col_gen.write_frac(vec_row, type_u.into(), denom);
                    }
                    logup_col_gen.finalize_col();
                }
            };
        }
    }

    fn add_constraints<E: stwo_constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let lookup_elements: &Range256LookupElements = lookup_elements.as_ref();

        // Add checked occurrences to logup sum.
        for col in Self::CHECKED_WORDS.iter() {
            // not using trace_eval! macro because it doesn't accept *col as an argument.
            let value = trace_eval.column_eval::<WORD_SIZE>(*col);
            for limb in value.into_iter().take(WORD_SIZE) {
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    SecureField::one().into(),
                    &[limb],
                ));
            }
        }

        for col in Self::CHECKED_HALF_WORDS.iter() {
            let value = trace_eval.column_eval::<2>(*col);
            for limb in value.into_iter().take(2) {
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    SecureField::one().into(),
                    &[limb],
                ));
            }
        }

        for col in Self::CHECKED_BYTES.iter() {
            let [value] = trace_eval.column_eval(*col);

            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                SecureField::one().into(),
                &[value],
            ));
        }

        for col in Self::TYPE_U_CHECKED_BYTES.iter() {
            let [value] = trace_eval.column_eval(*col);
            let [numerator] = virtual_column::IsTypeU::eval(trace_eval);

            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                numerator.into(),
                &[value],
            ));
        }
    }
}

fn fill_main_cols<const N: usize>(value_col: [BaseField; N], side_note: &mut SideNote) {
    for (_limb_index, limb) in value_col.iter().enumerate() {
        let checked = limb.0;
        #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
        assert!(checked < 256, "value[{_limb_index}] is out of range");
        side_note.range256.multiplicity[checked as usize] += 1;
    }
}

fn check_bytes<const N: usize>(
    basecolumn: [&BaseColumn; N],
    log_size: u32,
    logup_trace_gen: &mut LogupTraceGenerator,
    lookup_element: &Range256LookupElements,
) {
    // TODO: we can deal with two limbs at a time.
    for limb in basecolumn.iter() {
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

    use crate::extensions::ExtensionComponent;
    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::program_trace::{ProgramTraceRef, ProgramTracesBuilder};
    use crate::trace::{preprocessed::PreprocessedBuilder, Word};
    use crate::traits::MachineChip;

    use nexus_vm::emulator::{Emulator, HarvardEmulator, ProgramInfo};

    use stwo::core::fields::m31::BaseField;

    #[test]
    fn test_range256_chip_success() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default().finalize());
        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let buf: Word = array::from_fn(|i| (row_idx + i) as u8);

            traces.fill_columns_bytes(row_idx, &buf, ValueA);
            traces.fill_columns_bytes(row_idx, &buf, ValueB);
            traces.fill_columns_bytes(row_idx, &buf, ValueC);

            Range256Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        assert_chip::<Range256Chip>(traces, None);
    }

    #[test]
    fn test_range256_chip_fail_out_of_range_release() {
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
        for row_idx in 0..traces.num_rows() {
            let buf: [BaseField; WORD_SIZE] = array::from_fn(|i| {
                let t = ((row_idx + i) as u8) as u32;
                BaseField::from(t)
            });
            traces.fill_columns_base_field(row_idx, &buf, ValueB);

            Range256Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(ProgramStep::default()),
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        // modify looked up value
        *traces.column_mut::<{ ValueB.size() }>(12, ValueB)[0] = BaseField::from(256u32);

        let CommittedTraces {
            claimed_sum,
            lookup_elements,
            ..
        } = commit_traces::<Range256Chip>(config, &twiddles, &traces.finalize(), None);

        // verify that logup sums don't match
        let ext = ExtensionComponent::multiplicity256();
        let component_trace = ext.generate_component_trace(
            256u32.trailing_zeros(),
            program_trace_ref,
            &mut side_note,
        );
        let (_, claimed_sum_2) =
            ext.generate_interaction_trace(component_trace, &side_note, &lookup_elements);
        assert_ne!(claimed_sum + claimed_sum_2, SecureField::zero());
    }
}
