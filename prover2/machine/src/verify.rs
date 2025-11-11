use num_traits::Zero;
use stwo::{
    core::{
        air::Component,
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
        poly::circle::CanonicCoset,
        proof::StarkProof,
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
        verifier::VerificationError,
    },
    prover::{backend::simd::SimdBackend, poly::circle::PolyOps, CommitmentSchemeProver},
};
use stwo_constraint_framework::TraceLocationAllocator;

use nexus_vm::emulator::View;
use nexus_vm_prover_trace::eval::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

use super::{Proof, BASE_COMPONENTS};
use crate::{
    components::PrivateMemoryBoundary, lookups::AllLookupElements,
    side_note::program::ProgramTraceRef,
};

pub fn verify(proof: Proof, view: &View) -> Result<(), VerificationError> {
    let components = BASE_COMPONENTS;
    let Proof {
        stark_proof: proof,
        claimed_sums,
        log_sizes: claimed_log_sizes,
    } = proof;

    if claimed_sums.len() != components.len() {
        return Err(VerificationError::InvalidStructure(
            "claimed sums len mismatch".to_string(),
        ));
    }
    if claimed_log_sizes.len() != components.len() {
        return Err(VerificationError::InvalidStructure(
            "log sizes len mismatch".to_string(),
        ));
    }

    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sChannel::default();
    for &byte in view.view_associated_data().as_deref().unwrap_or_default() {
        verifier_channel.mix_u64(byte.into());
    }
    claimed_log_sizes.iter().for_each(|log_size| {
        verifier_channel.mix_u64(*log_size as u64);
    });

    verify_preprocessed_trace(&proof, view, verifier_channel, &claimed_log_sizes)?;

    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let sizes: Vec<TreeVec<Vec<u32>>> = components
        .iter()
        .zip(&claimed_log_sizes)
        .map(|(c, &log_size)| c.trace_sizes(log_size))
        .collect();
    let mut log_sizes = TreeVec::concat_cols(sizes.into_iter());
    log_sizes[PREPROCESSED_TRACE_IDX] = components
        .iter()
        .zip(&claimed_log_sizes)
        .flat_map(|(c, &log_size)| c.preprocessed_trace_sizes(log_size))
        .collect();

    for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
        commitment_scheme.commit(proof.commitments[idx], &log_sizes[idx], verifier_channel);
    }

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, verifier_channel));

    verify_logup_sum(&claimed_sums, view, &lookup_elements)?;

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: Vec<Box<dyn Component>> = components
        .iter()
        .zip(&claimed_sums)
        .zip(claimed_log_sizes)
        .map(|((comp, claimed_sum), log_size)| {
            comp.to_component(tree_span_provider, &lookup_elements, log_size, *claimed_sum)
        })
        .collect();
    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();

    verifier_channel.mix_felts(&claimed_sums);
    commitment_scheme.commit(
        proof.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        verifier_channel,
    );

    stwo::core::verifier::verify(&components_ref, verifier_channel, commitment_scheme, proof)
}

pub fn verify_preprocessed_trace(
    proof: &StarkProof<Blake2sMerkleHasher>,
    view: &View,
    verifier_channel: &mut Blake2sChannel,
    log_sizes: &[u32],
) -> Result<(), VerificationError> {
    let program = ProgramTraceRef::new(view);

    let components = BASE_COMPONENTS;
    let max_constraint_log_degree_bound = components
        .iter()
        .zip(log_sizes)
        .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);

    let config = PcsConfig::default();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let commitment_scheme =
        &mut CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    for (c, log_size) in components.iter().zip(log_sizes) {
        tree_builder.extend_evals(c.generate_preprocessed_trace(*log_size, &program));
    }
    tree_builder.commit(verifier_channel);

    let preprocessed_expected = commitment_scheme.roots()[PREPROCESSED_TRACE_IDX];
    let preprocessed = proof.commitments[PREPROCESSED_TRACE_IDX];
    if preprocessed_expected != preprocessed {
        Err(VerificationError::InvalidStructure(format!("invalid commitment to preprocessed trace: \
                                                         expected {preprocessed_expected}, got {preprocessed}")))
    } else {
        Ok(())
    }
}

pub fn verify_logup_sum(
    claimed_sums: &[SecureField],
    view: &View,
    lookup_elements: &AllLookupElements,
) -> Result<(), VerificationError> {
    let program = ProgramTraceRef::new(view);

    let memory_boundary =
        PrivateMemoryBoundary::expected_logup_sum(&program, lookup_elements.as_ref());
    if claimed_sums.iter().sum::<SecureField>() - memory_boundary != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }
    Ok(())
}
