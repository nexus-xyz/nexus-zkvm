pub(crate) mod bit_rotate;
pub(crate) mod bitwise_table;
pub(crate) mod memory_check;
pub(crate) mod round;

pub(crate) use bitwise_table::{BitNotAndTable, XorTable};
pub(crate) use memory_check::PermutationMemoryCheck;
pub(crate) use round::{KeccakRound, LANE_SIZE};

use super::ExtensionComponent;

pub const fn keccak_extensions() -> &'static [ExtensionComponent] {
    &[
        ExtensionComponent::PermutationMemoryCheck(PermutationMemoryCheck { _private: () }),
        ExtensionComponent::KeccakRound(KeccakRound {
            index: 0,
            rounds: 1 << 4,
            offset: 0,
        }),
        ExtensionComponent::KeccakRound(KeccakRound {
            index: 1,
            rounds: 1 << 3,
            offset: 1 << 4,
        }),
        ExtensionComponent::XorTable(XorTable {
            _phantom: std::marker::PhantomData,
        }),
        ExtensionComponent::BitNotAndTable(BitNotAndTable {
            _phantom: std::marker::PhantomData,
        }),
        ExtensionComponent::BitRotateTable(bit_rotate::BitRotateTable { _private: () }),
    ]
}

#[cfg(test)]
mod tests {
    use crate::{
        chips::{custom::KeccakChip, LoadStoreChip},
        components::AllLookupElements,
        extensions::{ComponentTrace, ExtensionsConfig},
        machine::{BaseComponent, Machine},
        trace::{
            program_trace::{ProgramTraceRef, ProgramTracesBuilder},
            sidenote::SideNote,
        },
        traits::MachineChip,
    };
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use stwo_prover::{
        constraint_framework::{
            TraceLocationAllocator, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
        },
        core::{
            air::ComponentProver,
            backend::simd::{m31::LOG_N_LANES, SimdBackend},
            channel::Blake2sChannel,
            pcs::{CommitmentSchemeProver, PcsConfig},
            poly::circle::{CanonicCoset, PolyOps},
            vcs::blake2_merkle::Blake2sMerkleChannel,
        },
    };

    use super::keccak_extensions;

    #[test]
    fn prove_keccak() {
        // test that keccak components constraints are satisfied and logup sum is zero.
        // running full protocol is required because stwo assert framework only works with a single component.

        // gen empty view for the side note
        let basic_block = vec![BasicBlock::new(vec![])];
        let (view, _) = k_trace_direct(&basic_block, 1).expect("error generating trace");
        let program_trace_ref = ProgramTraceRef {
            program_memory: view.get_program_memory(),
            init_memory: view.get_initial_memory(),
            exit_code: view.get_exit_code(),
            public_output: view.get_public_output(),
        };

        let program_traces =
            ProgramTracesBuilder::new_with_empty_memory(LOG_N_LANES, view.get_program_memory());
        let mut side_note = SideNote::new(&program_traces, &view);

        // input for keccak
        let log_n_instances = 4;
        let input_len = (1 << log_n_instances) - 1;
        let mut rng = ChaCha12Rng::from_seed(Default::default());
        let inputs: Vec<[u64; 25]> =
            std::iter::repeat_with(|| std::array::from_fn(|_idx| rng.next_u64()))
                .take(input_len)
                .collect();
        side_note.keccak.inputs = inputs;
        // addr carries
        side_note.keccak.addresses = vec![0xFFFF - 1; input_len];
        side_note.keccak.timestamps = vec![vec![0xFFFF - 1; 200]; input_len];

        // setup protocol
        const MAX_LOG_SIZE: u32 = 12;
        let config = PcsConfig::default();
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(MAX_LOG_SIZE + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        let prover_channel = &mut Blake2sChannel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        let components = keccak_extensions();
        let log_sizes: Vec<u32> = components
            .iter()
            .map(|ext| ext.compute_log_size(&side_note))
            .collect();

        let traces: Vec<ComponentTrace> = components
            .iter()
            .zip(&log_sizes)
            .map(|(ext, log_size)| {
                ext.generate_component_trace(*log_size, program_trace_ref, &mut side_note)
            })
            .collect();

        let mut tree_builder = commitment_scheme.tree_builder();
        for trace in &traces {
            tree_builder.extend_evals(trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
        }
        tree_builder.commit(prover_channel);
        let mut tree_builder = commitment_scheme.tree_builder();
        for trace in &traces {
            tree_builder.extend_evals(trace.to_circle_evaluation(ORIGINAL_TRACE_IDX));
        }
        tree_builder.commit(prover_channel);

        let mut lookup_elements = AllLookupElements::default();
        <(LoadStoreChip, KeccakChip)>::draw_lookup_elements(
            &mut lookup_elements,
            prover_channel,
            &ExtensionsConfig::from(keccak_extensions()),
        );

        let mut claimed_sums = vec![];
        let mut tree_builder = commitment_scheme.tree_builder();
        for (ext, trace) in components.iter().zip(traces) {
            let (interaction_trace, claimed_sum) =
                ext.generate_interaction_trace(trace, &side_note, &lookup_elements);
            tree_builder.extend_evals(interaction_trace);
            claimed_sums.push(claimed_sum);
        }

        // Not zero because of memory checking
        //
        // assert_eq!(
        //     claimed_sums.iter().sum::<SecureField>(),
        //     SecureField::zero()
        // );

        tree_builder.commit(prover_channel);
        let tree_span_provider = &mut TraceLocationAllocator::default();
        let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = components
            .iter()
            .zip(claimed_sums)
            .zip(log_sizes)
            .map(|((c, claimed_sum), log_size)| {
                c.to_component_prover(tree_span_provider, &lookup_elements, log_size, claimed_sum)
            })
            .collect();
        let components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
            components.iter().map(|c| &**c).collect();
        stwo_prover::core::prover::prove::<SimdBackend, Blake2sMerkleChannel>(
            &components_ref,
            prover_channel,
            commitment_scheme,
        )
        .expect("prove failed");
    }

    #[test]
    fn prove_execution_with_keccak() {
        let mut instructions = vec![
            // First we create a usable address. heap start: 528392, heap end: 8917000
            // Aiming to create 0x81008
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 1, 1, 19),
            // here x1 should be 0x80000
            // Adding x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            // Now x2 should be 0x81008
        ];
        let keccakf_inst = Instruction::new_ir(
            Opcode::new(0b1011010, Some(0b000), None, "keccakf"),
            2,
            0,
            0,
        );
        instructions.extend(vec![keccakf_inst; 20]);

        let basic_block = vec![BasicBlock::new(instructions)];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let proof = Machine::<BaseComponent>::prove_with_extensions(
            keccak_extensions(),
            &program_trace,
            &view,
        )
        .unwrap();
        Machine::<BaseComponent>::verify_with_extensions(
            keccak_extensions(),
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
