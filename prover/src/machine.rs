use std::marker::PhantomData;

use num_traits::Zero;
use stwo_prover::{
    constraint_framework::TraceLocationAllocator,
    core::{
        air::{Component, ComponentProver},
        backend::simd::SimdBackend,
        channel::{Blake2sChannel, Channel},
        fields::qm31::SecureField,
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig, TreeVec},
        poly::circle::{CanonicCoset, PolyOps},
        prover::{prove, verify, ProvingError, StarkProof, VerificationError},
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    },
};

use super::trace::eval::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};
use super::trace::{
    program::iter_program_steps, program_trace::ProgramTracesBuilder, sidenote::SideNote,
    PreprocessedTraces, TracesBuilder,
};
use nexus_vm::{
    emulator::{InternalView, MemoryInitializationEntry, ProgramInfo, PublicOutputEntry, View},
    trace::Trace,
};

use super::components::{MachineComponent, MachineEval, LOG_CONSTRAINT_DEGREE};
use super::traits::MachineChip;
use crate::{
    chips::{
        AddChip, AuipcChip, BeqChip, BgeChip, BgeuChip, BitOpChip, BltChip, BltuChip, BneChip,
        CpuChip, DecodingCheckChip, JalChip, JalrChip, LoadStoreChip, LuiChip, ProgramMemCheckChip,
        RangeCheckChip, RegisterMemCheckChip, SllChip, SltChip, SltuChip, SraChip, SrlChip,
        SubChip, SyscallChip, TimestampChip,
    },
    column::{PreprocessedColumn, ProgramColumn},
    components::{self, AllLookupElements},
    extensions::{ComponentTrace, ExtensionComponent},
    trace::program_trace::ProgramTraceRef,
    traits::generate_interaction_trace,
};
use serde::{Deserialize, Serialize};
/// Base component tuple for constraining virtual machine execution based on RV32I ISA.
pub type BaseComponent = (
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
    SyscallChip,
    ProgramMemCheckChip,
    RegisterMemCheckChip,
    TimestampChip,
    // Range checks must be positioned at the end. They use values filled by instruction chips.
    RangeCheckChip,
);
/// Base extensions used in conjunction with [`BaseComponent`]. These components are always enabled and are not accessible
/// to downstream crates. ram_init_final() modifies multiplicities for multiplicity256(), so the ordering between these is important.
const BASE_EXTENSIONS: &[ExtensionComponent] = &[
    ExtensionComponent::final_reg(),
    ExtensionComponent::bit_op_multiplicity(),
    ExtensionComponent::ram_init_final(),
    ExtensionComponent::multiplicity8(),
    ExtensionComponent::multiplicity16(),
    ExtensionComponent::multiplicity32(),
    ExtensionComponent::multiplicity128(),
    ExtensionComponent::multiplicity256(),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub stark_proof: StarkProof<Blake2sMerkleHasher>,
    pub claimed_sum: Vec<SecureField>, // one per component
    pub log_size: Vec<u32>,            // one per component
}

impl Proof {
    /// Similarly to [`StarkProof::size_estimate`] returns the proof size estimate in bytes.
    pub fn size_estimate(&self) -> usize {
        let Self {
            stark_proof,
            claimed_sum,
            log_size,
        } = self;
        stark_proof.size_estimate()
            + claimed_sum.len() * std::mem::size_of::<SecureField>()
            + log_size.len() * std::mem::size_of::<u32>()
    }
}

/// Main (empty) struct implementing proving functionality of zkVM.
///
/// The generic parameter determines which chips are enabled. The default is [`BaseComponent`] for RV32I ISA.
/// This functionality mainly exists for testing and removing a component **does not** remove columns it uses in the AIR.
///
/// Note that the order of chips affects correctness, e.g. if columns used by a component require additional lookups,
/// then it should be positioned in the front.
pub struct Machine<C = BaseComponent> {
    _phantom_data: PhantomData<C>,
}

impl<C: MachineChip + Sync> Machine<C> {
    pub fn prove(trace: &impl Trace, view: &View) -> Result<Proof, ProvingError> {
        Self::prove_with_extensions(&[], trace, view)
    }

    pub fn prove_with_extensions(
        extensions: &[ExtensionComponent],
        trace: &impl Trace,
        view: &View,
    ) -> Result<Proof, ProvingError> {
        let num_steps = trace.get_num_steps();
        let program_len = view.get_program_memory().program.len();
        let log_size =
            Self::max_log_size(&[num_steps, program_len]).max(PreprocessedTraces::MIN_LOG_SIZE);

        let extensions_iter = BASE_EXTENSIONS.iter().chain(extensions);

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
        for byte in view.view_associated_data().unwrap_or_default() {
            prover_channel.mix_u64(byte.into());
        }

        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // Fill columns of the preprocessed trace.
        let preprocessed_trace = PreprocessedTraces::new(log_size);

        // Fill columns of the original trace.
        let mut prover_traces = TracesBuilder::new(log_size);
        let program_trace_ref = ProgramTraceRef {
            program_memory: view.get_program_memory(),
            init_memory: view.get_initial_memory(),
            exit_code: view.get_exit_code(),
            public_output: view.get_public_output(),
        };
        let program_traces = ProgramTracesBuilder::new(log_size, program_trace_ref);
        let mut prover_side_note = SideNote::new(&program_traces, view);
        let program_steps = iter_program_steps(trace, prover_traces.num_rows());
        for (row_idx, program_step) in program_steps.enumerate() {
            C::fill_main_trace(
                &mut prover_traces,
                row_idx,
                &program_step,
                &mut prover_side_note,
            );
        }

        let finalized_trace = prover_traces.finalize();
        let finalized_program_trace = program_traces.finalize();

        let all_log_size: Vec<u32> = std::iter::once(log_size)
            .chain(
                extensions_iter
                    .clone()
                    .map(|ext| ext.compute_log_size(&prover_side_note)),
            )
            .collect();

        all_log_size.iter().for_each(|log_size| {
            prover_channel.mix_u64(*log_size as u64);
        });

        let mut tree_builder = commitment_scheme.tree_builder();
        let _preprocessed_trace_location = tree_builder.extend_evals(
            preprocessed_trace
                .clone()
                .into_circle_evaluation()
                .into_iter()
                .chain(finalized_program_trace.clone().into_circle_evaluation()),
        );

        let extension_traces: Vec<ComponentTrace> = extensions_iter
            .clone()
            .zip(all_log_size.get(1..).unwrap_or_default())
            .map(|(ext, log_size)| {
                ext.generate_component_trace(*log_size, program_trace_ref, &mut prover_side_note)
            })
            .collect();
        // Handle extensions for the preprocessed trace
        for extension_trace in &extension_traces {
            tree_builder.extend_evals(extension_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
        }
        tree_builder.commit(prover_channel);

        let mut tree_builder = commitment_scheme.tree_builder();
        let _main_trace_location =
            tree_builder.extend_evals(finalized_trace.clone().into_circle_evaluation());
        // Handle extensions for the main trace
        for extension_trace in &extension_traces {
            tree_builder.extend_evals(extension_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX));
        }
        tree_builder.commit(prover_channel);

        let mut lookup_elements = AllLookupElements::default();
        C::draw_lookup_elements(&mut lookup_elements, prover_channel);

        let (interaction_trace, claimed_sum) = generate_interaction_trace::<C>(
            &finalized_trace,
            &preprocessed_trace,
            &finalized_program_trace,
            &lookup_elements,
        );

        let mut tree_builder = commitment_scheme.tree_builder();
        let _interaction_trace_location = tree_builder.extend_evals(interaction_trace);
        // Handle extensions for the interaction trace
        let mut all_claimed_sum = vec![claimed_sum];
        for (ext, extension_trace) in extensions_iter.clone().zip(extension_traces) {
            let (interaction_trace, claimed_sum) = ext.generate_interaction_trace(
                extension_trace,
                &prover_side_note,
                &lookup_elements,
            );
            all_claimed_sum.push(claimed_sum);
            tree_builder.extend_evals(interaction_trace);
        }
        tree_builder.commit(prover_channel);

        let tree_span_provider = &mut TraceLocationAllocator::default();
        let main_component = MachineComponent::new(
            tree_span_provider,
            MachineEval::<C>::new(log_size, lookup_elements.clone()),
            claimed_sum,
        );
        let ext_components: Vec<Box<dyn ComponentProver<SimdBackend>>> = extensions_iter
            .zip(all_claimed_sum.get(1..).unwrap_or_default())
            .zip(all_log_size.get(1..).unwrap_or_default())
            .map(|((ext, claimed_sum), log_size)| {
                ext.to_component_prover(
                    tree_span_provider,
                    &lookup_elements,
                    *log_size,
                    *claimed_sum,
                )
            })
            .collect();
        let mut components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
            ext_components.iter().map(|c| &**c).collect();
        components_ref.insert(0, &main_component);
        let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
            &components_ref,
            prover_channel,
            commitment_scheme,
        )?;

        Ok(Proof {
            stark_proof: proof,
            claimed_sum: all_claimed_sum,
            log_size: all_log_size,
        })
    }

    pub fn verify(
        proof: Proof,
        program_info: &ProgramInfo,
        ad: &[u8],
        init_memory: &[MemoryInitializationEntry],
        exit_code: &[PublicOutputEntry],
        output_memory: &[PublicOutputEntry],
    ) -> Result<(), VerificationError> {
        Self::verify_with_extensions(
            &[],
            proof,
            program_info,
            ad,
            init_memory,
            exit_code,
            output_memory,
        )
    }

    pub fn verify_with_extensions(
        extensions: &[ExtensionComponent],
        proof: Proof,
        program_info: &ProgramInfo,
        ad: &[u8],
        init_memory: &[MemoryInitializationEntry],
        exit_code: &[PublicOutputEntry],
        output_memory: &[PublicOutputEntry],
    ) -> Result<(), VerificationError> {
        let Proof {
            stark_proof: proof,
            claimed_sum,
            log_size: all_log_sizes,
        } = proof;

        if claimed_sum.len() != extensions.len() + BASE_EXTENSIONS.len() + 1 {
            return Err(VerificationError::InvalidStructure(
                "claimed sum len mismatch".to_string(),
            ));
        }
        if all_log_sizes.len() != extensions.len() + BASE_EXTENSIONS.len() + 1 {
            return Err(VerificationError::InvalidStructure(
                "log size len mismatch".to_string(),
            ));
        }
        if claimed_sum.iter().sum::<SecureField>() != SecureField::zero() {
            return Err(VerificationError::InvalidStructure(
                "claimed logup sum is not zero".to_string(),
            ));
        }
        let extensions_iter = BASE_EXTENSIONS.iter().chain(extensions);

        let config = PcsConfig::default();
        let verifier_channel = &mut Blake2sChannel::default();
        for &byte in ad {
            verifier_channel.mix_u64(byte.into());
        }
        all_log_sizes.iter().for_each(|log_size| {
            verifier_channel.mix_u64(*log_size as u64);
        });

        let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

        // simulate the prover and compute expected commitment to preprocessed trace
        {
            let config = PcsConfig::default();
            let verifier_channel = &mut verifier_channel.clone();
            let twiddles = SimdBackend::precompute_twiddles(
                CanonicCoset::new(
                    all_log_sizes[0] + LOG_CONSTRAINT_DEGREE + config.fri_config.log_blowup_factor,
                )
                .circle_domain()
                .half_coset,
            );
            let commitment_scheme =
                &mut CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
                    config, &twiddles,
                );
            let preprocessed_trace = PreprocessedTraces::new(all_log_sizes[0]);
            let program_trace_ref = ProgramTraceRef {
                program_memory: program_info,
                init_memory,
                exit_code,
                public_output: output_memory,
            };
            let program_trace =
                ProgramTracesBuilder::new(all_log_sizes[0], program_trace_ref).finalize();

            let mut tree_builder = commitment_scheme.tree_builder();
            let _preprocessed_trace_location = tree_builder.extend_evals(
                preprocessed_trace
                    .into_circle_evaluation()
                    .into_iter()
                    .chain(program_trace.into_circle_evaluation()),
            );
            // Handle extensions for the preprocessed trace
            for (ext, log_size) in extensions_iter
                .clone()
                .zip(all_log_sizes.get(1..).unwrap_or_default())
            {
                tree_builder
                    .extend_evals(ext.generate_preprocessed_trace(*log_size, program_trace_ref));
            }
            tree_builder.commit(verifier_channel);

            let preprocessed_expected = commitment_scheme.roots()[PREPROCESSED_TRACE_IDX];
            let preprocessed = proof.commitments[PREPROCESSED_TRACE_IDX];
            if preprocessed_expected != preprocessed {
                return Err(VerificationError::InvalidStructure(format!("invalid commitment to preprocessed trace: \
                                                                        expected {preprocessed_expected}, got {preprocessed}")));
            }
        }

        // Retrieve the expected column sizes in each commitment interaction, from the AIR.

        // Info evaluation can be avoided if the prover sends lookup elements along with the proof, this requires
        // implementing  [`serde::Serialize`] for all relations and [`AllLookupElements`]. Note that the verifier
        // should still independently draw elements and match it against received ones.
        let mut sizes = vec![components::machine_component_info::<C>()
            .mask_offsets
            .as_cols_ref()
            .map_cols(|_| all_log_sizes[0])];
        for (ext, log_size) in extensions_iter
            .clone()
            .zip(all_log_sizes.get(1..).unwrap_or_default())
        {
            sizes.push(ext.trace_sizes(*log_size));
        }
        let mut log_sizes = TreeVec::concat_cols(sizes.into_iter());
        // use the fact that preprocessed columns are only allowed to have [0] mask
        log_sizes[PREPROCESSED_TRACE_IDX] = std::iter::repeat(all_log_sizes[0])
            .take(PreprocessedColumn::COLUMNS_NUM + ProgramColumn::COLUMNS_NUM)
            .collect();
        for (ext, log_size) in extensions_iter
            .clone()
            .zip(all_log_sizes.get(1..).unwrap_or_default())
        {
            // extending log_sizes[PREPROCESSED_TRACE_IDX] with the dimension of the preprocessed columns
            log_sizes[PREPROCESSED_TRACE_IDX].extend(ext.preprocessed_trace_sizes(*log_size));
        }

        for idx in [PREPROCESSED_TRACE_IDX, ORIGINAL_TRACE_IDX] {
            commitment_scheme.commit(proof.commitments[idx], &log_sizes[idx], verifier_channel);
        }

        let mut lookup_elements = AllLookupElements::default();
        C::draw_lookup_elements(&mut lookup_elements, verifier_channel);

        let tree_span_provider = &mut TraceLocationAllocator::default();
        let main_component = MachineComponent::new(
            tree_span_provider,
            MachineEval::<C>::new(all_log_sizes[0], lookup_elements.clone()),
            claimed_sum[0],
        );

        let ext_components: Vec<Box<dyn Component>> = extensions_iter
            .zip(claimed_sum.get(1..).unwrap_or_default())
            .zip(all_log_sizes.get(1..).unwrap_or_default())
            .map(|((ext, claimed_sum), log_size)| {
                ext.to_component(
                    tree_span_provider,
                    &lookup_elements,
                    *log_size,
                    *claimed_sum,
                )
            })
            .collect();
        let mut components_ref: Vec<&dyn Component> = ext_components.iter().map(|c| &**c).collect();
        components_ref.insert(0, &main_component);

        commitment_scheme.commit(
            proof.commitments[INTERACTION_TRACE_IDX],
            &log_sizes[INTERACTION_TRACE_IDX],
            verifier_channel,
        );

        verify(&components_ref, verifier_channel, commitment_scheme, proof)
    }

    /// Computes minimum allowed log_size from a slice of lengths.
    fn max_log_size(sizes: &[usize]) -> u32 {
        sizes
            .iter()
            .map(|size| size.next_power_of_two().trailing_zeros())
            .max()
            .expect("sizes is empty")
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

        let proof = Machine::<BaseComponent>::prove(&program_trace, &view).unwrap();
        Machine::<BaseComponent>::verify(
            proof,
            view.get_program_memory(),
            &[],
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }
}
