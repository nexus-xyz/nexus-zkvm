use num_traits::Zero;
use stwo_prover::{
    constraint_framework::TraceLocationAllocator,
    core::{
        air::Component,
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec},
        prover::{self, VerificationError},
        vcs::blake2_merkle::Blake2sMerkleChannel,
    },
};

use nexus_vm_prover_trace::eval::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

use super::{Proof, BASE_COMPONENTS};
use crate::lookups::AllLookupElements;

pub fn verify(proof: Proof, ad: &[u8]) -> Result<(), VerificationError> {
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
    if claimed_sums.iter().sum::<SecureField>() != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(
            "claimed logup sum is not zero".to_string(),
        ));
    }

    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sChannel::default();
    for &byte in ad {
        verifier_channel.mix_u64(byte.into());
    }

    claimed_log_sizes.iter().for_each(|log_size| {
        verifier_channel.mix_u64(*log_size as u64);
    });

    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // TODO: verify commitment to the preprocessed trace
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

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let verifier_components: Vec<Box<dyn Component>> = components
        .iter()
        .zip(claimed_sums)
        .zip(claimed_log_sizes)
        .map(|((comp, claimed_sum), log_size)| {
            comp.to_component(tree_span_provider, &lookup_elements, log_size, claimed_sum)
        })
        .collect();
    let components_ref: Vec<&dyn Component> = verifier_components.iter().map(|c| &**c).collect();

    commitment_scheme.commit(
        proof.commitments[INTERACTION_TRACE_IDX],
        &log_sizes[INTERACTION_TRACE_IDX],
        verifier_channel,
    );

    prover::verify(&components_ref, verifier_channel, commitment_scheme, proof)
}
