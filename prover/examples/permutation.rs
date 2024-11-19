// This file contains some derived work of stwo codebase

// Copyright 2024 StarkWare Industries Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This example constrains (a0, a1, ...)s to be a permutation of (b0, b1, ...)s
// Columns (a0, a1, ...) and (b0, b1, ...) are constrained to be permutations of each other,
// in other words, equals as multisets of M31 * M31 * ... * M31.

use array2d::Array2D;
use byte_unit::Byte;
use clap::Parser;
// TODO: figure out a safe way to expose the is_first column to the verifier
use itertools::Itertools;
use num_traits::{One, Zero};
use std::{
    panic,
    time::{Duration, Instant},
};

use nexus_vm_prover::{
    machine2::trace::utils::coset_order_to_circle_domain_order,
    utils::{generate_trace, EvalAtRowExtra},
};
use stwo_prover::{
    constraint_framework::{
        assert_constraints,
        logup::{LogupAtRow, LogupTraceGenerator, LookupElements},
        EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
        INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
    },
    core::{
        air::Component,
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        channel::Blake2sChannel,
        fields::{m31::BaseField, qm31::SecureField},
        fri::FriConfig,
        lookups::utils::Fraction,
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig, TreeSubspan},
        poly::{
            circle::{CanonicCoset, CircleEvaluation, PolyOps},
            BitReversedOrder,
        },
        prover::{prove, verify, StarkProof},
        utils::bit_reverse,
        vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
        ColumnVec,
    },
};

// Maybe useful for other examples
trait IterBaseField {
    fn iter_base_field(&self) -> impl Iterator<Item = BaseField>;
}

impl IterBaseField for [BaseField; N_TUPLE_ELM] {
    fn iter_base_field(&self) -> impl Iterator<Item = BaseField> {
        self.iter().copied()
    }
}

struct Statistics {
    pub proof_time: Duration,
    pub verify_time: Duration,
    pub proof_size: usize,
}

fn print_statistics(stat: Statistics) {
    println!(
        "Proof time: {}",
        humantime::format_duration(stat.proof_time)
    );
    println!(
        "Verify time: {}",
        humantime::format_duration(stat.verify_time)
    );
    let readable_proof_size =
        Byte::from(stat.proof_size).get_appropriate_unit(byte_unit::UnitType::Decimal);
    println!("Proof size: {}", readable_proof_size);
}

// Things below are specific to this example.

pub type PermComponent = FrameworkComponent<PermEval>;

const N_TUPLE_ELM: usize = 12;

#[derive(Clone)]
pub struct PermEval {
    pub log_n_rows: u32,
    pub base_trace_location: TreeSubspan,
    pub perm_element: LookupElements<N_TUPLE_ELM>,
}

impl FrameworkEval for PermEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let [is_first] = eval.next_interaction_mask(PREPROCESSED_TRACE_IDX, [0]);
        // The constraints aim at guaranteeing (a0, a1) and (b0, b1) to be permutations
        let a: [E::F; N_TUPLE_ELM] = eval.next_trace_masks();
        let b: [E::F; N_TUPLE_ELM] = eval.next_trace_masks();

        let mut logup =
            LogupAtRow::<_>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        let denom_a: E::EF = self.perm_element.combine(&a);
        let denom_b: E::EF = self.perm_element.combine(&b);

        logup.write_frac(&mut eval, Fraction::new(SecureField::one().into(), denom_a));
        logup.write_frac(
            &mut eval,
            Fraction::new((-SecureField::one()).into(), denom_b),
        );
        logup.finalize(&mut eval);

        eval
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PermCircuitTraceStep {
    pub a: [BaseField; N_TUPLE_ELM],
    pub b: [BaseField; N_TUPLE_ELM],
}

impl IterBaseField for PermCircuitTraceStep {
    fn iter_base_field(&self) -> impl Iterator<Item = BaseField> {
        self.a.iter_base_field().chain(self.b.iter_base_field())
    }
}

struct PermCircuitTrace {
    pub log_sizes: Vec<u32>,
    pub table: Array2D<BaseField>,
}

fn gen_trace(
    basic_trace: &PermCircuitTrace,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    generate_trace(basic_trace.log_sizes.clone(), |cols| {
        cols.iter_mut().enumerate().for_each(|(col_idx, col)| {
            let column_orig = basic_trace
                .table
                .column_iter(col_idx)
                .unwrap()
                .copied()
                .enumerate();
            column_orig.for_each(|(row_idx, cell_orig)| {
                col[row_idx] = cell_orig;
            });
        });
    })
}

struct PermCircuitTraceForLogup {
    pub a_column: [BaseColumn; N_TUPLE_ELM],
    pub b_column: [BaseColumn; N_TUPLE_ELM],
}

fn gen_perm_circuit_trace_for_logup(basic_trace: &PermCircuitTrace) -> PermCircuitTraceForLogup {
    let a_column = basic_trace
        .table
        .columns_iter()
        .take(N_TUPLE_ELM)
        .map(|column_iter| {
            let mut col =
                coset_order_to_circle_domain_order(column_iter.copied().collect_vec().as_slice());
            bit_reverse(&mut col);
            BaseColumn::from_iter(col)
        })
        .collect_vec()
        .try_into()
        .expect("wrong size?");
    let b_column = basic_trace
        .table
        .columns_iter()
        .skip(N_TUPLE_ELM)
        .take(N_TUPLE_ELM)
        .map(|column_iter| {
            let mut col =
                coset_order_to_circle_domain_order(column_iter.copied().collect_vec().as_slice());
            bit_reverse(&mut col);
            BaseColumn::from_iter(col)
        })
        .collect_vec()
        .try_into()
        .expect("wrong size?");
    PermCircuitTraceForLogup { a_column, b_column }
}

fn gen_interaction_trace(
    log_n_rows: u32,
    basic_trace: &PermCircuitTrace,
    perm_element: &LookupElements<N_TUPLE_ELM>,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let basic_trace = gen_perm_circuit_trace_for_logup(basic_trace);
    // Note: LogupTraceGenerator internally allocates ColumnVec; so generate_secure_fiele_trace() cannot be used.
    let mut trace_gen = LogupTraceGenerator::new(log_n_rows);

    // Add tuples in 'a'
    let mut col_gen = trace_gen.new_col();
    for vec_row in 0..(1 << (log_n_rows - LOG_N_LANES)) {
        let tuple = (0..N_TUPLE_ELM)
            .map(|i| basic_trace.a_column[i].data[vec_row])
            .collect_vec();
        let denom = perm_element.combine(&tuple[..]);
        col_gen.write_frac(vec_row, SecureField::one().into(), denom);
    }
    col_gen.finalize_col();

    // Subtract tuples in 'b'
    let mut col_gen = trace_gen.new_col();
    for vec_row in 0..(1 << (log_n_rows - LOG_N_LANES)) {
        let tuple = (0..N_TUPLE_ELM)
            .map(|i| basic_trace.b_column[i].data[vec_row])
            .collect_vec();
        let denom = perm_element.combine(&tuple[..]);
        col_gen.write_frac(vec_row, (-SecureField::one()).into(), denom);
    }
    col_gen.finalize_col();

    let (ret, total) = trace_gen.finalize_last();
    debug_assert_eq!(total, SecureField::zero());
    ret
}

fn gen_constant_trace(
    log_n_rows: u32,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    generate_trace([log_n_rows], |cols| {
        cols[0][0] = 1.into();
    })
}

fn trace_steps_to_trace(trace: &PermCircuitTrace) -> [BaseColumn; N_TUPLE_ELM * 2] {
    trace
        .table
        .columns_iter()
        .map(|column_iter| BaseColumn::from_iter(column_iter.copied()))
        .collect_vec()
        .try_into()
        .expect("wrong size?")
}

#[allow(unused)]
fn prove_perm(
    log_n_rows: u32,
    config: PcsConfig,
    basic_trace: PermCircuitTrace,
) -> (PermComponent, StarkProof<Blake2sMerkleHasher>) {
    assert!(log_n_rows >= LOG_N_LANES);

    let n_rows = 1 << log_n_rows;
    let range = 0..n_rows;
    let mut circuit = trace_steps_to_trace(&basic_trace);

    // Precompute twiddles.
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );

    // Setup protocol.
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

    // Constant trace. This is a separate interaction because we send the commitment for
    // the constant trace to the verifier.
    let trace = gen_constant_trace(log_n_rows);
    let mut tree_builder = commitment_scheme.tree_builder();
    let constant_trace_location = tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Trace.
    let trace = gen_trace(&basic_trace);
    let mut tree_builder = commitment_scheme.tree_builder();
    let base_trace_location = tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Draw permutation element
    let perm_element = LookupElements::draw(channel);

    // Interaction trace.
    let trace = gen_interaction_trace(log_n_rows, &basic_trace, &perm_element);
    let mut tree_builder = commitment_scheme.tree_builder();
    let interaction_trace_location = tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    let component = PermComponent::new(
        &mut TraceLocationAllocator::default(),
        PermEval {
            log_n_rows,
            base_trace_location,
            perm_element,
        },
    );

    // Sanity check. Remove for production.
    if cfg!(debug_assertions) {
        println!("debug_assertions on");
        let trace_polys = commitment_scheme
            .trees
            .as_ref()
            .map(|t| t.polynomials.iter().cloned().collect_vec());
        assert_constraints(&trace_polys, CanonicCoset::new(log_n_rows), |mut eval| {
            component.evaluate(eval);
        });
    }

    // Prove constraints.
    let proof = prove(&[&component], channel, commitment_scheme).unwrap();

    (component, proof)
}

fn test_simd_perm_prove(log_n_instances: u32, basic_trace: PermCircuitTrace) -> Statistics {
    // Set FRI config
    let config = PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(5, 4, 64), // should I change this?
    };

    // Prove.
    let begin = Instant::now();
    let (component, proof) = prove_perm(log_n_instances, config, basic_trace);
    let proof_time: Duration = Instant::now() - begin;

    // Measure proof Size.
    let serialized_proof = bincode::serialize(&proof).expect("failed to serialize proof");
    let proof_size = serialized_proof.len();

    // Verify.
    // TODO: Create Air instance independently.
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // Decommit.
    // Retrieve the expected column sizes in each commitment interaction, from the AIR.
    let sizes = component.trace_log_degree_bounds();
    // Constant columns.
    commitment_scheme.commit(
        proof.commitments[PREPROCESSED_TRACE_IDX],
        &sizes[PREPROCESSED_TRACE_IDX],
        channel,
    );
    // Trace columns.
    commitment_scheme.commit(
        proof.commitments[ORIGINAL_TRACE_IDX],
        &sizes[ORIGINAL_TRACE_IDX],
        channel,
    );
    // Interaction columns.
    commitment_scheme.commit(
        proof.commitments[INTERACTION_TRACE_IDX],
        &sizes[INTERACTION_TRACE_IDX],
        channel,
    );

    let begin = Instant::now();
    verify(&[&component], channel, commitment_scheme, proof).unwrap();
    let verify_time: Duration = Instant::now() - begin;

    Statistics {
        proof_time,
        verify_time,
        proof_size,
    }
}

// Below are just for specific test cases
// a and b are permutations when gathered over i

// This fills a trace that satisfies the constraint.
#[allow(unused)]
fn should_work(log_n_rows: u32) -> PermCircuitTrace {
    let n_rows = 1 << log_n_rows;
    let range = 0..n_rows;
    // a and b are permutations
    let rows = range.map(|i| PermCircuitTraceStep {
        a: match i {
            2 => [11.into(); N_TUPLE_ELM],
            5 => [22.into(); N_TUPLE_ELM],
            8 => [33.into(); N_TUPLE_ELM],
            _ => [0.into(); N_TUPLE_ELM],
        },
        b: match i {
            3 => [22.into(); N_TUPLE_ELM],
            19 => [11.into(); N_TUPLE_ELM],
            22 => [33.into(); N_TUPLE_ELM],
            _ => [0.into(); N_TUPLE_ELM],
        },
    });
    let row_iter = rows.map(|step| step.iter_base_field().collect_vec());
    let row_major = row_iter.flatten();
    PermCircuitTrace {
        log_sizes: vec![log_n_rows; N_TUPLE_ELM * 2],
        table: Array2D::from_iter_row_major(row_major, n_rows, N_TUPLE_ELM * 2).unwrap(),
    }
}

#[allow(unused)]
fn one_element_missing(log_n_rows: u32) -> PermCircuitTrace {
    let range = 0..(1 << log_n_rows);
    // a and b are not permutations
    let rows = range.map(|i| PermCircuitTraceStep {
        a: match i {
            2 => [11.into(); N_TUPLE_ELM],
            5 => [22.into(); N_TUPLE_ELM],
            8 => [33.into(); N_TUPLE_ELM],
            _ => [0.into(); N_TUPLE_ELM],
        },
        b: match i {
            3 => [22.into(); N_TUPLE_ELM],
            19 => [11.into(); N_TUPLE_ELM],
            _ => [0.into(); N_TUPLE_ELM],
        },
    });
    let row_iter = rows.map(|step| step.iter_base_field().collect_vec());
    let row_major = row_iter.flatten();
    PermCircuitTrace {
        log_sizes: vec![log_n_rows; N_TUPLE_ELM * 2],
        table: Array2D::from_iter_row_major(row_major, 1 << log_n_rows, N_TUPLE_ELM * 2).unwrap(),
    }
}

fn run_success_case(log_n_instances: u32) {
    println!("=====Testing success case=====");
    let stat = test_simd_perm_prove(log_n_instances, should_work(log_n_instances));
    println!(
        "Proven and verified permutation of {} (M31 ^ {}) elements.",
        1 << log_n_instances,
        N_TUPLE_ELM
    );
    print_statistics(stat);
}

fn run_failure_case(log_n_instances: u32) {
    println!("=====Testing failure case=====");
    let result = panic::catch_unwind(|| {
        let _silencer = shh::stderr().unwrap();
        test_simd_perm_prove(log_n_instances, one_element_missing(log_n_instances));
    });
    assert!(result.is_err());
    println!("The failing example failed as expected. Permutation is really checked.");
}

// TODO: -r 5 on the debug build fails with an assertion failure. Investigate.
#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "7", value_parser = clap::value_parser!(u32).range(7..=28))]
    pub rows_log: u32,
}

fn main() {
    let cli = Cli::parse();

    run_success_case(cli.rows_log);
    run_failure_case(cli.rows_log);
}
