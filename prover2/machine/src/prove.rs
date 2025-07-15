use serde::{Deserialize, Serialize};
use stwo_prover::{
    constraint_framework::TraceLocationAllocator,
    core::{
        air::ComponentProver,
        backend::simd::SimdBackend,
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeProver, PcsConfig},
        poly::circle::{CanonicCoset, PolyOps},
        prover::{self, ProvingError, StarkProof},
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    },
};

use nexus_vm::{emulator::View, trace::Trace};
use nexus_vm_prover_trace::{
    component::ComponentTrace,
    eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
};

use super::BASE_COMPONENTS;
use crate::{lookups::AllLookupElements, side_note::SideNote};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub stark_proof: StarkProof<Blake2sMerkleHasher>,
    pub claimed_sums: Vec<SecureField>,
    pub log_sizes: Vec<u32>,
}

pub fn prove(trace: &impl Trace, view: &View) -> Result<Proof, ProvingError> {
    let mut prover_side_note = SideNote::new(trace, view);
    let components = BASE_COMPONENTS;

    let traces: Vec<ComponentTrace> = components
        .iter()
        .map(|c| c.generate_component_trace(&mut prover_side_note))
        .collect();
    let log_sizes: Vec<u32> = traces.iter().map(ComponentTrace::log_size).collect();

    let max_constraint_log_degree_bound = components
        .iter()
        .zip(&log_sizes)
        .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
        .max()
        .unwrap_or(0);

    // Precompute twiddles.
    let config = PcsConfig::default();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    // Setup protocol.
    let prover_channel = &mut Blake2sChannel::default();
    for byte in view.view_associated_data().unwrap_or_default() {
        prover_channel.mix_u64(byte.into());
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    log_sizes.iter().for_each(|log_size| {
        prover_channel.mix_u64(*log_size as u64);
    });

    // Preprocessed trace.
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        let _preprocessed_trace_location =
            tree_builder.extend_evals(component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);

    // Main trace.
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        let _main_trace_location =
            tree_builder.extend_evals(component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);

    let mut lookup_elements = AllLookupElements::default();
    components
        .iter()
        .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, prover_channel));

    // Interaction trace.
    let mut tree_builder = commitment_scheme.tree_builder();
    let claimed_sums: Vec<SecureField> = components
        .iter()
        .zip(traces)
        .map(|(c, component_trace)| {
            let (interaction_trace, claimed_sum) =
                c.generate_interaction_trace(component_trace, &prover_side_note, &lookup_elements);
            tree_builder.extend_evals(interaction_trace);

            claimed_sum
        })
        .collect();
    tree_builder.commit(prover_channel);

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = components
        .iter()
        .zip(&log_sizes)
        .zip(&claimed_sums)
        .map(|((c, log_size), claimed_sum)| {
            c.to_component_prover(
                tree_span_provider,
                &lookup_elements,
                *log_size,
                *claimed_sum,
            )
        })
        .collect();
    let components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
        components.iter().map(|c| &**c).collect();

    let proof = prover::prove::<SimdBackend, Blake2sMerkleChannel>(
        &components_ref,
        prover_channel,
        commitment_scheme,
    )?;

    Ok(Proof {
        stark_proof: proof,
        claimed_sums,
        log_sizes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    #[test]
    fn prove_verify() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let proof = prove(&program_trace, &view).unwrap();
        verify(proof, &[]).unwrap();
    }
}
