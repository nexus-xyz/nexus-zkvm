// This file contains range-checking values for 0..=255.

use stwo_prover::{
    constraint_framework::logup::{LogupTraceGenerator, LookupElements},
    core::fields::m31,
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

use crate::machine2::{
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval},
        trace_column_mut, ProgramStep, Traces,
    },
    traits::MachineChip,
};

use crate::machine2::column::Column::{self, *};
use crate::machine2::column::PreprocessedColumn::{self, *};

/// A Chip for range-checking values for 0..=255
///
/// Range256Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range256Chip;

impl Range256Chip {
    const CHECKED: [Column; 3] = [ValueA, ValueB, ValueC];
}

impl MachineChip for Range256Chip {
    /// Increments Multiplicity256 for every number checked
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, _step: &ProgramStep) {
        for col in Self::CHECKED.iter() {
            // not using trace_column! because it doesn't accept *col as an argument.
            let value_col: [BaseField; WORD_SIZE] = traces.column(row_idx, *col);
            fill_main_word(value_col, traces);
        }
        // TODO: check the other columns, too.
    }
    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        original_traces: &Traces,
        preprocessed_traces: &Traces,
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

        let (ret, total_logup_sum) = logup_trace_gen.finalize_last();
        debug_assert_eq!(total_logup_sum, SecureField::zero());
        ret
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::machine2::trace::eval::TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let (_, [is_first]) = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum.
        for col in Self::CHECKED.iter() {
            // not using trace_eval! macro because it doesn't accept *col as an argument.
            let (_, value) = trace_eval.column_eval::<WORD_SIZE>(*col);
            for limb_idx in 0..WORD_SIZE {
                let denom: E::EF = lookup_elements.combine(&[value[limb_idx].clone()]);
                logup.write_frac(eval, Fraction::new(SecureField::one().into(), denom));
            }
        }
        // Subtract looked up multiplicites from logup sum.
        let (_, [range]) = preprocessed_trace_eval!(trace_eval, Range256);
        let (_, [multiplicity]) = trace_eval!(trace_eval, Multiplicity256);
        let denom: E::EF = lookup_elements.combine(&[range.clone()]);
        let numerator: E::EF = (-multiplicity.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
    }
}

fn fill_main_word(value_a_col: [BaseField; WORD_SIZE], traces: &mut Traces) {
    let mut counter: u32 = 0;
    for limb_index in 0..WORD_SIZE {
        let checked = value_a_col[limb_index].0;
        debug_assert!(checked < 256, "value[{}] is out of range", limb_index);
        let multiplicity_col: [&mut BaseField; 1] =
            trace_column_mut!(traces, checked as usize, Multiplicity256);
        *multiplicity_col[0] += BaseField::one();
        // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
        assert_ne!(*multiplicity_col[0], BaseField::zero());
        // Detect global overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
        counter += 1;
        assert_ne!(counter, m31::P);
    }
}

fn check_word_limbs(
    basecolumn: [BaseColumn; WORD_SIZE],
    log_size: u32,
    logup_trace_gen: &mut LogupTraceGenerator,
    lookup_element: &LookupElements<12>,
) {
    // TODO: we can deal with two limbs at a time.
    for limb_idx in 0..WORD_SIZE {
        let mut logup_col_gen = logup_trace_gen.new_col();
        // vec_row is row_idx divided by 16. Because SIMD.
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let checked_tuple = vec![basecolumn[limb_idx].data[vec_row]];
            let denom = lookup_element.combine(&checked_tuple);
            logup_col_gen.write_frac(vec_row, SecureField::one().into(), denom);
        }
        logup_col_gen.finalize_col();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::machine2::components::{MachineComponent, MachineEval};
    use crate::machine2::trace::eval::TraceEval;
    use crate::machine2::traits::MachineChip;

    use itertools::Itertools;
    use stwo_prover::constraint_framework::{assert_constraints, TraceLocationAllocator};
    use stwo_prover::core::channel::Blake2sChannel;
    use stwo_prover::core::fields::m31::BaseField;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::{CommitmentSchemeProver, PcsConfig, TreeVec};
    use stwo_prover::core::poly::circle::{CanonicCoset, PolyOps};
    use stwo_prover::core::prover::prove;
    use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel;

    pub type Component = MachineComponent<Range256Chip>;

    #[test]
    fn test_range256_chip_success() {
        const LOG: u32 = 8;
        let mut traces = Traces::new(LOG);
        // Write in-range values to ValueA columns.
        for row_idx in 0..(1 << LOG) {
            for i in 0..WORD_SIZE {
                let val: usize = (row_idx + i) % 256;
                let value_row = trace_column_mut!(traces, row_idx, ValueA);
                *value_row[i] = BaseField::from(val);
                let value_row = trace_column_mut!(traces, row_idx, ValueB);
                *value_row[i] = BaseField::from(val);
                let value_row = trace_column_mut!(traces, row_idx, ValueC);
                *value_row[i] = BaseField::from(val);
            }
            Range256Chip::fill_main_trace(&mut traces, row_idx, &ProgramStep::default());
        }
        assert_range256_chip(traces, LOG);
    }

    // The test range256_chip_fail_out_of_range() fails with different messages
    // depending on debug_assertion is enabled or not. The release mode is more interesting
    // because it fails in the low-degree checking.
    #[test]
    #[cfg(not(debug_assertions))]
    #[should_panic(expected = "ConstraintsNotSatisfied")]
    fn test_range256_chip_fail_out_of_range_release() {
        range256_chip_fail_out_of_range();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "out of range")]
    fn test_range256_chip_fail_out_of_range_debug() {
        range256_chip_fail_out_of_range();
    }

    fn range256_chip_fail_out_of_range() {
        const LOG: u32 = 9;
        let (config, twiddles) = test_params(LOG);
        let mut traces = Traces::new(LOG);
        // Write in-range values to ValueA columns.
        for row_idx in 0..(1 << LOG) {
            for i in 0..WORD_SIZE {
                let val: usize = (row_idx + i) % 256;
                let value_row = trace_column_mut!(traces, row_idx, ValueB);
                *value_row[i] = BaseField::from(val + 1); // sometimes out of range
            }
            Range256Chip::fill_main_trace(&mut traces, row_idx, &ProgramStep::default());
        }
        let (mut commitment_scheme, mut prover_channel, lookup_element, _, _) =
            commit_traces(LOG, config, &twiddles, &traces);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<Range256Chip>::new(LOG, lookup_element),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }

    fn commit_traces<'a>(
        log_size: u32,
        config: PcsConfig,
        twiddles: &'a stwo_prover::core::poly::twiddles::TwiddleTree<SimdBackend>,
        traces: &Traces,
    ) -> (
        CommitmentSchemeProver<'a, SimdBackend, Blake2sMerkleChannel>,
        Blake2sChannel,
        LookupElements<12>,
        Traces,                                                          // Preprocessed trace
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>, // Interaction trace
    ) {
        let mut commitment_scheme =
            CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);
        let mut prover_channel = Blake2sChannel::default();
        // Preprocessed trace
        let preprocessed_traces = Traces::new_preprocessed_trace(log_size);
        let mut tree_builder = commitment_scheme.tree_builder();
        let _preprocessed_trace_location =
            tree_builder.extend_evals(preprocessed_traces.circle_evaluation());
        tree_builder.commit(&mut prover_channel);

        // Original trace
        let mut tree_builder = commitment_scheme.tree_builder();
        let _main_trace_location = tree_builder.extend_evals(traces.circle_evaluation());
        tree_builder.commit(&mut prover_channel);
        let lookup_element = LookupElements::draw(&mut prover_channel);

        // Interaction Trace
        let interaction_trace =
            Range256Chip::fill_interaction_trace(&traces, &preprocessed_traces, &lookup_element);
        let mut tree_builder = commitment_scheme.tree_builder();
        let _interaction_trace_location = tree_builder.extend_evals(interaction_trace.clone());
        tree_builder.commit(&mut prover_channel);
        (
            commitment_scheme,
            prover_channel,
            lookup_element,
            preprocessed_traces,
            interaction_trace,
        )
    }

    fn assert_range256_chip(traces: Traces, log_size: u32) {
        let (config, twiddles) = test_params(log_size);

        let (_, _, lookup_element, preprocessed_traces, interaction_trace) =
            commit_traces(log_size, config, &twiddles, &traces);

        let traces = TreeVec::new(vec![
            preprocessed_traces.circle_evaluation(),
            traces.circle_evaluation(),
            interaction_trace
                .iter()
                .map(|col| col.to_cpu())
                .collect_vec(),
        ]);
        let trace_polys = traces.map(|trace| {
            trace
                .into_iter()
                .map(|c| c.interpolate())
                .collect::<Vec<_>>()
        });

        // Now check the constraints to make sure they're satisfied
        assert_constraints(&trace_polys, CanonicCoset::new(log_size), |mut eval| {
            let trace_eval = TraceEval::new(&mut eval);
            Range256Chip::add_constraints(&mut eval, &trace_eval, &lookup_element);
        });
    }

    fn test_params(
        log_size: u32,
    ) -> (
        PcsConfig,
        stwo_prover::core::poly::twiddles::TwiddleTree<SimdBackend>,
    ) {
        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig::new(5, 4, 64), // should I change this?
        };
        let twiddles = SimdBackend::precompute_twiddles(
            // The + 1 is taken from the stwo examples. I don't know why it's needed.
            CanonicCoset::new(log_size + config.fri_config.log_blowup_factor + 1)
                .circle_domain()
                .half_coset,
        );
        (config, twiddles)
    }
}
