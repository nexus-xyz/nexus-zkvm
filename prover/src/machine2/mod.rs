use std::marker::PhantomData;

use stwo_prover::{
    constraint_framework::{logup::LookupElements, TraceLocationAllocator},
    core::{
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        pcs::{CommitmentSchemeProver, PcsConfig},
        poly::circle::{CanonicCoset, PolyOps},
        prover::{prove, ProvingError, StarkProof},
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    },
};

use nexus_vm::trace::Trace;
use trace::ProgramStep;

pub mod chips;
pub mod components;
pub mod trace;

pub mod column;
pub mod traits;

pub use crate::utils::WORD_SIZE;

use chips::{AddChip, CpuChip};
use components::{MachineComponent, MachineEval, LOG_CONSTRAINT_DEGREE};
use traits::MachineChip;

pub type Components = (CpuChip, AddChip);
pub type Proof = StarkProof<Blake2sMerkleHasher>;

pub struct Machine<C = Components> {
    _phantom_data: PhantomData<C>,
}

impl<C: MachineChip + Sync> Machine<C> {
    pub fn prove(trace: &impl Trace) -> Result<Proof, ProvingError> {
        const LOG_SIZE: u32 = 6;

        let config = PcsConfig::default();
        // Precompute twiddles.
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(
                LOG_SIZE + LOG_CONSTRAINT_DEGREE + config.fri_config.log_blowup_factor,
            )
            .circle_domain()
            .half_coset,
        );

        // Setup protocol.
        let prover_channel = &mut Blake2sChannel::default();
        let commitment_scheme =
            &mut CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
                config, &twiddles,
            );

        // Fill columns.
        let mut prover_traces = trace::Traces::new(LOG_SIZE);
        for (row_idx, block) in trace.get_blocks_iter().enumerate() {
            // k = 1
            assert_eq!(block.steps.len(), 1);

            let step = ProgramStep {
                step: block.steps[0].clone(),
                regs: block.regs,
            };
            C::fill_main_trace(&mut prover_traces, row_idx, &step);
        }
        let mut tree_builder = commitment_scheme.tree_builder();
        let _main_trace_location = tree_builder.extend_evals(prover_traces.circle_evaluation());
        tree_builder.commit(prover_channel);

        let lookup_elements = LookupElements::draw(prover_channel);
        let preprocessed_trace = trace::Traces::new_preprocessed_trace(LOG_SIZE);
        let mut tree_builder = commitment_scheme.tree_builder();
        let interaction_trace =
            C::fill_interaction_trace(&prover_traces, &preprocessed_trace, &lookup_elements);
        let _interaction_trace_location = tree_builder.extend_evals(interaction_trace);
        tree_builder.commit(prover_channel);

        // Fill columns of the preprocessed trace.
        let mut tree_builder = commitment_scheme.tree_builder();
        let _preprocessed_trace_location =
            tree_builder.extend_evals(preprocessed_trace.circle_evaluation());
        tree_builder.commit(prover_channel);

        let component = MachineComponent::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<C>::new(LOG_SIZE),
        );
        let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
            &[&component],
            prover_channel,
            commitment_scheme,
        )?;

        Ok(proof)
    }
}
