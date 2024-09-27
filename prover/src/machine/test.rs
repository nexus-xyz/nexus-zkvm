// Simple addition machine
// This machine performs only additions. It has a STARK-trace with
// numbers in [0, 32): 'r1_idx', 'r2_idx', and 'rd_idx'.
// and 32-bit numbers: 'r1_val', 'r2_val', and 'rd_val'.
// r1_idx and r2_idx are indices of input registers (they can be the same).
// rd_idx is the index of the output register.
// r1_val and r2_val are the values of the input registers before the addition is executed.
// rd_val is the value of the output register after the addition is executed.
// Each 32-bit number is represented by four columns, one for each byte.
// TODO: These columns WILL BE range-checked to be an 8-bit integer.

// TODO: Register memory checking
// Clock for Register Memory Checking
// 0 is used for initializing the register file.
// 4 is used for reading the rs_1 for the first instruction.
// 5 is used for reading the rs_2 for the first instruction.
// 6 is used for writing the rd for the first instruction.
// 8..11 is used for reading the rs_1, rs_2, and writing the rd for the second instruction.
// and so on.

// CLK column will contain (4,8,12,16,...).
// For reading rs_1 value, the timestamp CLK will be used.
// For reading rs_2 value, the timestamp CLK+1 will be used.
// For writing rd value, the timestamp CLK+2 will be used.

// Reading from a register idx i. If i is zero, no events are recorded. If i is nonzero, we look at the register file to determine the last time stamp and the value of the register.
// Then we record a ReadSetElement(register_index=i, prev_timestamp, prev_value).
// We also record a WriteSetElement(register_index=i, current_timestamp, prev_value). The prev_value is reused because reading the register does not change the value.
// Writing to a register idx i. The index i should not be zero. We look at the register file to determine the last time stamp and the value of the register.
// We record a ReadSetElement(register_index=i, prev_timestamp, prev_value).
// We also record a WriteSetElement(register_index=i, current_timestamp, new_value). The prev_value is reused because reading the register does not change the value.
// In both cases prev_timestamp < current_timestamp must be constrained. This should be implemented with lookups on limbs.
// For that, the technique used for "xor with lookups" will be useful.

// TODO: write somewhere in the trace, the initial values of registers.
// TODO: write somewhere in the trace, the final values and timestamps of registers.
// TODO: calculate register memory check logup sum

use rand::rngs;
use strum::IntoEnumIterator;
use stwo_prover::{
    constraint_framework::{
        assert_constraints, FrameworkComponent, FrameworkEval as _, TraceLocationAllocator,
    },
    core::{
        air::Component,
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig},
        poly::circle::{CanonicCoset, PolyOps},
        prover::{prove, verify},
        vcs::blake2_merkle::Blake2sMerkleChannel,
    },
};

use crate::{
    machine::{
        chips::{add::AddChip, sub::SubChip, xor::XorChip},
        eval::EvalMachine,
        honest_traces::main_trace,
        register_file::AddMachineRegisterFile,
        types::{column_sizes, ColumnName},
    },
    utils::{ColumnNameMap, PermElements},
};

#[test]
fn test_machine() {
    let rows_log2 = 16;
    debug_assert!(rows_log2 >= 16); // XOR lookup table takes 2^16 rows
    let column_names: ColumnNameMap<ColumnName> = ColumnNameMap::new()
        .allocate_bulk(ColumnName::iter().map(|x| (x, column_sizes(&x))))
        .finalize();
    let config = PcsConfig::default();
    let coset = CanonicCoset::new(rows_log2 + 1 + config.fri_config.log_blowup_factor)
        .circle_domain()
        .half_coset;
    let twiddles = SimdBackend::precompute_twiddles(coset);
    let allocator = &mut TraceLocationAllocator::default();
    let prover_channel = &mut Blake2sChannel::default();
    let prover_commitment_scheme =
        &mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut rng = rngs::OsRng;
    let mut reg_file = AddMachineRegisterFile::new(&mut rng);
    type Chips = (AddChip, SubChip, XorChip);
    let (main_trace, basic_trace) =
        main_trace::<Chips>(&mut rng, &mut reg_file, rows_log2, &column_names);
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_trace);
    tree_builder.commit(prover_channel);

    // Draw permutation element
    let xor_perm_element = PermElements::draw(prover_channel);
    let machine = EvalMachine::<Chips> {
        rows_log2: rows_log2,
        cols: column_names,
        xor_perm_element,
        _phantom: std::marker::PhantomData,
    };

    // Interaction trace.
    let interaction_trace = machine.interaction_trace(&basic_trace);
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(prover_channel);

    // Constraint trace.
    let constant_trace = machine.constant_trace();
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(constant_trace);
    tree_builder.commit(prover_channel);

    // Sanity check
    // Comment this out before release for performance.

    let traces = prover_commitment_scheme
        .trees
        .as_ref()
        .map(|t| t.polynomials.to_vec());

    assert_constraints(&traces, CanonicCoset::new(rows_log2), |evaluator| {
        machine.evaluate(evaluator);
    });

    let component = FrameworkComponent::new(allocator, machine);
    let proof =
        prove(&[&component], prover_channel, prover_commitment_scheme).expect("failed to prove");

    // verifier
    let verifier_channel = &mut Blake2sChannel::default();
    let verifier_commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let verifier_component_sizes = component.trace_log_degree_bounds();

    for i in 0..3 {
        verifier_commitment_scheme.commit(
            proof.commitments[i],
            &verifier_component_sizes[i],
            verifier_channel,
        )
    }
    verify(
        &[&component],
        verifier_channel,
        verifier_commitment_scheme,
        proof,
    )
    .expect("proof verification failed");

    println!("{} machine cycles proved and verified", 1 << rows_log2);
}
