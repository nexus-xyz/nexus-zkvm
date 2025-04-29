use stwo_prover::{
    constraint_framework::{assert_constraints, EvalAtRow},
    core::{
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        fields::{m31::BaseField, qm31::SecureField},
        pcs::{CommitmentSchemeProver, PcsConfig, TreeVec},
        poly::{
            circle::{CanonicCoset, CircleEvaluation, PolyOps},
            BitReversedOrder,
        },
        vcs::blake2_merkle::Blake2sMerkleChannel,
    },
};

use crate::{
    components::{AllLookupElements, LOG_CONSTRAINT_DEGREE},
    extensions::ExtensionsConfig,
    trace::{program_trace::ProgramTracesBuilder, FinalizedTraces, PreprocessedTraces},
    traits::generate_interaction_trace,
};

use super::{
    trace::{eval::TraceEval, program_trace::ProgramTraces, TracesBuilder},
    traits::MachineChip,
};

pub(crate) fn test_params(
    log_size: u32,
) -> (
    PcsConfig,
    stwo_prover::core::poly::twiddles::TwiddleTree<SimdBackend>,
) {
    let config = PcsConfig::default();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + config.fri_config.log_blowup_factor + LOG_CONSTRAINT_DEGREE)
            .circle_domain()
            .half_coset,
    );
    (config, twiddles)
}

/// Filled out traces, mainly for testing
pub(crate) struct CommittedTraces<'a> {
    pub(crate) commitment_scheme: CommitmentSchemeProver<'a, SimdBackend, Blake2sMerkleChannel>,
    pub(crate) prover_channel: Blake2sChannel,
    pub(crate) lookup_elements: AllLookupElements,
    pub(crate) preprocessed_trace: PreprocessedTraces,
    pub(crate) interaction_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub(crate) claimed_sum: SecureField,
    pub(crate) program_trace: ProgramTraces,
}

/// Testing utility for filling in traces
pub(crate) fn commit_traces<'a, C: MachineChip>(
    config: PcsConfig,
    twiddles: &'a stwo_prover::core::poly::twiddles::TwiddleTree<SimdBackend>,
    traces: &FinalizedTraces,
    program_traces: Option<ProgramTraces>,
) -> CommittedTraces<'a> {
    let mut commitment_scheme =
        CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, twiddles);
    let mut prover_channel = Blake2sChannel::default();

    let program_trace =
        program_traces.unwrap_or_else(|| ProgramTracesBuilder::dummy(traces.log_size()).finalize());
    // Preprocessed trace
    let preprocessed_trace = PreprocessedTraces::new(traces.log_size());
    let mut tree_builder = commitment_scheme.tree_builder();
    let _preprocessed_trace_location = tree_builder.extend_evals(
        preprocessed_trace
            .clone()
            .into_circle_evaluation()
            .into_iter()
            .chain(program_trace.clone().into_circle_evaluation()),
    );
    tree_builder.commit(&mut prover_channel);

    // Original trace
    let mut tree_builder = commitment_scheme.tree_builder();
    let _main_trace_location = tree_builder.extend_evals(traces.clone().into_circle_evaluation());
    tree_builder.commit(&mut prover_channel);
    let mut all_elements = AllLookupElements::default();
    C::draw_lookup_elements(
        &mut all_elements,
        &mut prover_channel,
        &ExtensionsConfig::default(),
    );

    // Interaction Trace
    let (interaction_trace, claimed_sum) =
        generate_interaction_trace::<C>(traces, &preprocessed_trace, &program_trace, &all_elements);
    let mut tree_builder = commitment_scheme.tree_builder();
    let _interaction_trace_location = tree_builder.extend_evals(interaction_trace.clone());
    tree_builder.commit(&mut prover_channel);

    CommittedTraces {
        commitment_scheme,
        prover_channel,
        lookup_elements: all_elements,
        preprocessed_trace,
        interaction_trace,
        claimed_sum,
        program_trace,
    }
}

/// Assuming traces are filled, assert constraints
pub(crate) fn assert_chip<C: MachineChip>(
    traces: TracesBuilder,
    program_trace: Option<ProgramTraces>,
) -> (AllLookupElements, SecureField) {
    let (config, twiddles) = test_params(traces.log_size());

    let finalized_trace = traces.finalize();
    let log_size = finalized_trace.log_size();

    let CommittedTraces {
        commitment_scheme: _,
        prover_channel: _,
        lookup_elements,
        preprocessed_trace,
        interaction_trace,
        claimed_sum,
        program_trace,
    } = commit_traces::<C>(config, &twiddles, &finalized_trace, program_trace);

    let trace_evals = TreeVec::new(vec![
        [
            preprocessed_trace.into_circle_evaluation(),
            program_trace.into_circle_evaluation(),
        ]
        .concat(),
        finalized_trace.into_circle_evaluation(),
        interaction_trace,
    ]);
    let trace_polys = trace_evals.map(|trace| {
        trace
            .into_iter()
            .map(|c| c.interpolate())
            .collect::<Vec<_>>()
    });

    // Now check the constraints to make sure they're satisfied
    assert_constraints(
        &trace_polys,
        CanonicCoset::new(log_size),
        |mut eval| {
            let trace_eval = TraceEval::new(&mut eval);
            C::add_constraints(
                &mut eval,
                &trace_eval,
                &lookup_elements,
                &ExtensionsConfig::default(),
            );

            if !lookup_elements.is_empty() {
                eval.finalize_logup();
            }
        },
        claimed_sum,
    );
    (lookup_elements, claimed_sum)
}
