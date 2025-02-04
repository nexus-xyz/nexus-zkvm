use std::marker::PhantomData;

use stwo_prover::{
    constraint_framework::{logup::LookupElements, TraceLocationAllocator},
    core::{
        air::Component,
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig},
        poly::circle::{CanonicCoset, PolyOps},
        prover::{prove, verify, ProvingError, StarkProof, VerificationError},
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    },
};

use super::trace::eval::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX, PROGRAM_TRACE_IDX,
};
use super::trace::{
    program::iter_program_steps, program_trace::ProgramTracesBuilder, sidenote::SideNote,
    PreprocessedTraces, TracesBuilder,
};
use nexus_vm::{emulator::View, trace::Trace};

use super::chips::{
    AddChip, AuipcChip, BeqChip, BgeChip, BgeuChip, BitOpChip, BltChip, BltuChip, BneChip, CpuChip,
    DecodingCheckChip, JalChip, JalrChip, LoadStoreChip, LuiChip, ProgramMemCheckChip,
    RangeCheckChip, RegisterMemCheckChip, SllChip, SltChip, SltuChip, SraChip, SrlChip, SubChip,
    TimestampChip,
};
use super::components::{MachineComponent, MachineEval, LOG_CONSTRAINT_DEGREE};
use super::traits::MachineChip;

/// Base components tuple for constraining virtual machine execution based on RV32I ISA.
pub type BaseComponents = (
    CpuChip,
    DecodingCheckChip,
    AddChip,
    SubChip,
    SltuChip,
    BitOpChip,
    SltChip,
    BneChip,
    BeqChip,
    BltuChip,
    BltChip,
    BgeuChip,
    BgeChip,
    JalChip,
    LuiChip,
    AuipcChip,
    JalrChip,
    SllChip,
    SrlChip,
    SraChip,
    LoadStoreChip,
    ProgramMemCheckChip,
    RegisterMemCheckChip,
    TimestampChip,
    // Range checks must be positioned at the end. They use values filled by instruction chips.
    RangeCheckChip,
);

#[derive(Debug)]
pub struct Proof {
    pub stark_proof: StarkProof<Blake2sMerkleHasher>,
    pub log_size: u32,
}

/// Main (empty) struct implementing proving functionality of zkVM.
///
/// The generic parameter determines which components are enabled. The default is [`BaseComponents`] for RV32I ISA.
/// This functionality mainly exists for testing and removing a component **does not** remove columns it uses in the AIR.
///
/// Note that the order of components affects correctness, e.g. if columns used by a component require additional lookups,
/// then it should be positioned in the front.
pub struct Machine<C = BaseComponents> {
    _phantom_data: PhantomData<C>,
}

impl<C: MachineChip + Sync> Machine<C> {
    pub fn prove<I>(
        trace: &impl Trace,
        view: &View,
        public_output_addresses: I,
    ) -> Result<Proof, ProvingError>
    where
        I: IntoIterator<Item = u32>,
    {
        let num_steps = trace.get_num_steps();
        let program_log_size = view
            .get_program_info()
            .program
            .len()
            .next_power_of_two()
            .trailing_zeros();
        let log_size: u32 = num_steps
            .next_power_of_two()
            .trailing_zeros()
            .max(PreprocessedTraces::MIN_LOG_SIZE)
            .max(program_log_size);

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
        let preprocessed_trace = PreprocessedTraces::new(log_size);

        // Fill columns of the original trace.
        let mut prover_traces = TracesBuilder::new(log_size);
        let mut program_traces = ProgramTracesBuilder::new(log_size, view.get_program_info());
        let mut prover_side_note = SideNote::new(&program_traces, view, public_output_addresses);
        let program_steps = iter_program_steps(trace, prover_traces.num_rows());
        for (row_idx, program_step) in program_steps.enumerate() {
            C::fill_main_trace(
                &mut prover_traces,
                row_idx,
                &program_step,
                &mut program_traces,
                &mut prover_side_note,
            );
        }

        let finalized_trace = prover_traces.finalize();
        let finalized_program_trace = program_traces.finalize();

        let lookup_elements = LookupElements::draw(prover_channel);
        let interaction_trace = C::fill_interaction_trace(
            &finalized_trace,
            &preprocessed_trace,
            &finalized_program_trace,
            &lookup_elements,
        );

        let mut tree_builder = commitment_scheme.tree_builder();
        let _preprocessed_trace_location =
            tree_builder.extend_evals(preprocessed_trace.into_circle_evaluation());
        tree_builder.commit(prover_channel);

        let mut tree_builder = commitment_scheme.tree_builder();
        let _main_trace_location =
            tree_builder.extend_evals(finalized_trace.into_circle_evaluation());
        tree_builder.commit(prover_channel);

        let mut tree_builder = commitment_scheme.tree_builder();
        let _interaction_trace_location = tree_builder.extend_evals(interaction_trace);
        tree_builder.commit(prover_channel);

        // Fill columns of the program trace.
        let mut tree_builder = commitment_scheme.tree_builder();
        let _program_trace_location =
            tree_builder.extend_evals(finalized_program_trace.into_circle_evaluation());
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

        Ok(Proof {
            stark_proof: proof,
            log_size,
        })
    }

    pub fn verify(proof: Proof) -> Result<(), VerificationError> {
        let Proof {
            stark_proof: proof,
            log_size,
        } = proof;

        let config = PcsConfig::default();
        let verifier_channel = &mut Blake2sChannel::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

        let lookup_elements = LookupElements::draw(verifier_channel);
        let component = MachineComponent::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<C>::new(log_size, lookup_elements),
        );

        // simulate the prover and compute expected commitment to preprocessed trace
        {
            let config = PcsConfig::default();
            let verifier_channel = &mut Blake2sChannel::default();
            let twiddles = SimdBackend::precompute_twiddles(
                CanonicCoset::new(
                    log_size + LOG_CONSTRAINT_DEGREE + config.fri_config.log_blowup_factor,
                )
                .circle_domain()
                .half_coset,
            );
            let commitment_scheme =
                &mut CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
                    config, &twiddles,
                );
            let preprocessed_trace = PreprocessedTraces::new(log_size);
            let mut tree_builder = commitment_scheme.tree_builder();
            let _preprocessed_trace_location =
                tree_builder.extend_evals(preprocessed_trace.into_circle_evaluation());
            tree_builder.commit(verifier_channel);

            let preprocessed_expected = commitment_scheme.roots()[PREPROCESSED_TRACE_IDX];
            let preprocessed = proof.commitments[PREPROCESSED_TRACE_IDX];
            if preprocessed_expected != preprocessed {
                return Err(VerificationError::InvalidStructure(format!("invalid commitment to preprocessed trace: \
                                                                        expected {preprocessed_expected}, got {preprocessed}")));
            }
            // TODO: verify commitment to the program trace
        }

        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let sizes = component.trace_log_degree_bounds();
        for idx in [
            PREPROCESSED_TRACE_IDX,
            ORIGINAL_TRACE_IDX,
            INTERACTION_TRACE_IDX,
            PROGRAM_TRACE_IDX,
        ] {
            commitment_scheme.commit(proof.commitments[idx], &sizes[idx], verifier_channel);
        }
        verify(&[&component], verifier_channel, commitment_scheme, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let proof = Machine::<BaseComponents>::prove(
            &program_trace,
            &view,
            program_trace.memory_layout.public_output_addresses(),
        )
        .unwrap();
        Machine::<BaseComponents>::verify(proof).unwrap();
    }
}
