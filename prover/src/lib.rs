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
use trace::{program::iter_program_steps, sidenote::SideNote};

pub mod chips;
pub mod components;
pub mod trace;

pub mod column;
pub mod traits;

#[cfg(test)]
mod test_utils;

pub(crate) use nexus_vm::WORD_SIZE;

use chips::{
    AddChip, BeqChip, BitOpChip, BltuChip, BneChip, CpuChip, Range128Chip, Range256Chip,
    Range32Chip, RangeBoolChip, SltChip, SltuChip, SubChip, TimestampChip,
};
use components::{MachineComponent, MachineEval, LOG_CONSTRAINT_DEGREE};
use traits::MachineChip;

pub type Components = (
    CpuChip,
    AddChip,
    SubChip,
    SltuChip,
    BitOpChip,
    SltChip,
    BneChip,
    BeqChip,
    BltuChip,
    TimestampChip,
    // Range checks must be positioned at the end. They use values filled by instruction chips.
    RangeBoolChip,
    Range128Chip,
    Range32Chip,
    Range256Chip,
);
pub type Proof = StarkProof<Blake2sMerkleHasher>;

pub struct Machine<C = Components> {
    _phantom_data: PhantomData<C>,
}

impl<C: MachineChip + Sync> Machine<C> {
    pub fn prove(trace: &impl Trace) -> Result<Proof, ProvingError> {
        let num_steps = trace.get_num_steps();
        let log_size: u32 = num_steps.next_power_of_two().trailing_zeros();

        let config = PcsConfig::default();
        // Precompute twiddles.
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(
                log_size + LOG_CONSTRAINT_DEGREE + config.fri_config.log_blowup_factor,
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

        // Fill columns of the preprocessed trace.
        let preprocessed_trace = trace::PreprocessedTraces::new(log_size);
        let mut tree_builder = commitment_scheme.tree_builder();
        let _preprocessed_trace_location =
            tree_builder.extend_evals(preprocessed_trace.circle_evaluation());
        tree_builder.commit(prover_channel);

        // Fill columns of the original trace.
        let mut prover_traces = trace::Traces::new(log_size);
        let mut prover_side_note = SideNote::default();
        let program_steps = iter_program_steps(trace, prover_traces.num_rows());
        for (row_idx, program_step) in program_steps.enumerate() {
            C::fill_main_trace(
                &mut prover_traces,
                row_idx,
                &program_step,
                &mut prover_side_note,
            );
        }

        let mut tree_builder = commitment_scheme.tree_builder();
        let _main_trace_location = tree_builder.extend_evals(prover_traces.circle_evaluation());
        tree_builder.commit(prover_channel);

        let lookup_elements = LookupElements::draw(prover_channel);
        let mut tree_builder = commitment_scheme.tree_builder();
        let interaction_trace =
            C::fill_interaction_trace(&prover_traces, &preprocessed_trace, &lookup_elements);
        let _interaction_trace_location = tree_builder.extend_evals(interaction_trace);
        tree_builder.commit(prover_channel);

        let component = MachineComponent::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<C>::new(log_size, lookup_elements),
        );
        let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
            &[&component],
            prover_channel,
            commitment_scheme,
        )?;

        Ok(proof)
    }
}
