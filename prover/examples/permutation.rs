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

// This example constrains (a0, a1)s to be a permutation of (b0, b1)s
// Columns (a0, a1) and (b0, b1) are constrained to be permutations of each other,
// in other words, equals as multisets of M31 * M31 * ... * M31.

use array2d::Array2D;
use byte_unit::Byte;
use clap::Parser;
// TODO: figure out a safe way to expose the is_first column to the verifier
use itertools::{zip_eq, Itertools};
use num_traits::{One, Zero};
use std::{
    array,
    ops::{Mul, Sub},
    panic,
    time::{Duration, Instant},
};

use nexus_vm_prover::utils::coset_order_to_circle_domain_order;
use stwo_prover::{
    constraint_framework::{
        assert_constraints, EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    },
    core::{
        air::Component,
        backend::{
            simd::{
                column::{BaseColumn, SecureColumn},
                m31::LOG_N_LANES,
                SimdBackend,
            },
            Column,
        },
        channel::{Blake2sChannel, Channel},
        fields::{
            m31::BaseField, qm31::SecureField, secure_column::SecureColumnByCoords, FieldExpOps,
        },
        fri::FriConfig,
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

// This is very similar to LookupElement in logup.rs.
// I'm avoiding logup.rs because it's not randomized preprocessed AIR.
// logup.rs puts claimed_sum (which is not a low-degree polynomial) as constant into constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermElements<const N: usize> {
    pub z: SecureField,
    pub alpha: SecureField,
    alpha_powers: [SecureField; N],
}
impl<const N: usize> PermElements<N> {
    pub fn draw(channel: &mut impl Channel) -> Self {
        let [z, alpha] = channel.draw_felts(2).try_into().unwrap();
        let mut cur = SecureField::one();
        let alpha_powers = std::array::from_fn(|_| {
            let res = cur;
            cur *= alpha;
            res
        });
        Self {
            z,
            alpha,
            alpha_powers,
        }
    }

    // The iterator needs to return [N] elements. Avoiding a slice because no need of
    // contiguous memory.
    pub fn combine<F: Copy, EF, I: IntoIterator<Item = F>>(&self, values: I) -> EF
    where
        EF: Copy + Zero + From<F> + From<SecureField> + Mul<F, Output = EF> + Sub<EF, Output = EF>,
    {
        zip_eq(values, self.alpha_powers).fold(EF::zero(), |acc, (value, power)| {
            acc + EF::from(power) * value
        }) - EF::from(self.z)
    }
}

fn to_bitreverse_eval_base_columns(base_column: &BaseColumn) -> BaseColumn {
    let mut eval = coset_order_to_circle_domain_order(base_column.as_slice());
    bit_reverse(&mut eval);
    BaseColumn::from_iter(eval)
}

fn reorder_secure_column_by_coords_for_eval(
    column: &mut SecureColumnByCoords<SimdBackend>,
) -> SecureColumnByCoords<SimdBackend> {
    let mut c_circle_domain = coset_order_to_circle_domain_order(column.to_vec().as_slice());
    bit_reverse(&mut c_circle_domain);
    SecureColumnByCoords::<SimdBackend>::from_iter(c_circle_domain)
}

trait EvalAtRowExtra: EvalAtRow {
    /// Returns the mask values of offset zero for the next C columns in the interaction zero.
    fn next_trace_masks<const C: usize>(&mut self) -> [Self::F; C] {
        array::from_fn(|_i| self.next_trace_mask())
    }
}

impl<T: EvalAtRow> EvalAtRowExtra for T {}

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
    pub perm_element: PermElements<N_TUPLE_ELM>,
}

impl FrameworkEval for PermEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Constant column
        let [is_first] = eval.next_interaction_mask(2, [0]);
        // The constraints aim at guaranteeing (a0, a1) and (b0, b1) to be permutations
        let a: [E::F; N_TUPLE_ELM] = eval.next_trace_masks();
        let b: [E::F; N_TUPLE_ELM] = eval.next_trace_masks();
        // a_denom_i = a_i - z (z is the challenge)
        let [a_denom] = eval.next_extension_interaction_mask(1, [0]);
        // 1/a_denom_i
        let [a_denom_inv] = eval.next_extension_interaction_mask(1, [0]);
        // Here -1 looks at the previous row.
        let [a_denom_inv_sum_prev, a_denom_inv_sum] =
            eval.next_extension_interaction_mask(1, [-1, 0]);
        let [b_denom] = eval.next_extension_interaction_mask(1, [0]);
        let [b_denom_inv] = eval.next_extension_interaction_mask(1, [0]);
        let [b_denom_inv_sum_prev, b_denom_inv_sum] =
            eval.next_extension_interaction_mask(1, [-1, 0]);

        // FIXME: we are assuming that the verifier knows is_first column, that has not happened yet

        // Constraints that determine a_denom_inv
        eval.add_constraint(self.perm_element.combine::<E::F, E::EF, _>(a) - a_denom);
        eval.add_constraint(a_denom * a_denom_inv - E::EF::one());

        // Constraint that determines a_denom_inv_sum on the first row
        // a_denom_inv_sum_0 = a_denom_inv_0
        eval.add_constraint((a_denom_inv_sum - a_denom_inv) * is_first);

        // Constraints that determine a_denom_inv_sum except on the first row
        eval.add_constraint(
            (a_denom_inv_sum - a_denom_inv - a_denom_inv_sum_prev) * (E::F::one() - is_first),
        );

        // Constraints that determine b_denom_inv
        eval.add_constraint(self.perm_element.combine::<E::F, E::EF, _>(b) - b_denom);
        eval.add_constraint(b_denom * b_denom_inv - E::EF::one());

        // Constraint that determines b_denom_inv_sum on the first row
        eval.add_constraint((b_denom_inv_sum - b_denom_inv) * is_first);

        // Constraints that determine b_denom_inv_sum except on the first row
        eval.add_constraint(
            (b_denom_inv_sum - b_denom_inv - b_denom_inv_sum_prev) * (E::F::one() - is_first),
        );

        // Compare sums
        eval.add_constraint((b_denom_inv_sum_prev - a_denom_inv_sum_prev) * is_first);

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
    pub inner: Array2D<BaseField>,
}

pub fn gen_trace(
    log_size: u32,
    circuit: &[BaseColumn; N_TUPLE_ELM * 2],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();

    circuit
        .iter()
        .map(|eval| CircleEvaluation::new(domain, to_bitreverse_eval_base_columns(eval)))
        .collect()
}

fn gen_interaction_trace(
    log_n_rows: u32,
    basic_trace: &PermCircuitTrace,
    perm_element: &PermElements<N_TUPLE_ELM>,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1 << log_n_rows;
    let range = 0..n_rows;

    let mut a_denom = SecureColumn::zeros(n_rows); // for batch inverse

    // Add a column of (a + z)'s
    basic_trace
        .inner
        .rows_iter()
        .enumerate()
        .for_each(|(row_idx, row_iter)| {
            let denom = perm_element.combine(row_iter.take(N_TUPLE_ELM).copied()); // TODO: too manual
            a_denom.set(row_idx, denom);
        });

    let mut a_denom_inv = SecureColumn::zeros(n_rows);
    FieldExpOps::batch_inverse(&a_denom.data, &mut a_denom_inv.data);

    // Add a column of 1/(a + z)'s
    let mut a_sum = SecureField::zero();
    let mut a_inv_sum = SecureColumn::zeros(n_rows);
    for row_index in range.clone() {
        a_sum += a_denom_inv.at(row_index);
        a_inv_sum.set(row_index, a_sum);
    }

    let mut b_denom = SecureColumn::zeros(n_rows); // for batch inverse

    // Add a column of (b + z)'s
    basic_trace
        .inner
        .rows_iter()
        .enumerate()
        .for_each(|(row_idx, row_iter)| {
            let denom = perm_element.combine(row_iter.skip(N_TUPLE_ELM).take(N_TUPLE_ELM).copied()); /* too manual */
            b_denom.set(row_idx, denom);
        });
    let mut b_denom_inv = SecureColumn::zeros(n_rows);
    FieldExpOps::batch_inverse(&b_denom.data, &mut b_denom_inv.data);

    // Add a column of 1/(b + z)'s
    let mut b_sum = SecureField::zero();
    let mut b_inv_sum = SecureColumn::zeros(n_rows);
    for row_index in range {
        b_sum += b_denom_inv.at(row_index);
        b_inv_sum.set(row_index, b_sum);
    }

    let trace = vec![
        a_denom,
        a_denom_inv,
        a_inv_sum,
        b_denom,
        b_denom_inv,
        b_inv_sum,
    ];

    trace
        .into_iter()
        .flat_map(|eval| {
            let mut eval = eval.into_secure_column_by_coords();
            let eval2 = reorder_secure_column_by_coords_for_eval(&mut eval);
            eval2
                .columns
                .map(|c| CircleEvaluation::new(CanonicCoset::new(log_n_rows).circle_domain(), c))
        })
        .collect_vec()
}

fn gen_constant_trace(
    log_n_rows: u32,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows: usize = 1 << log_n_rows;
    let range = 0..n_rows;
    let mut is_first_column =
        BaseColumn::from_iter(range.map(|i| if i == 0 { 1.into() } else { 0.into() }));
    is_first_column = to_bitreverse_eval_base_columns(&is_first_column);

    let domain = CanonicCoset::new(log_n_rows).circle_domain();

    [is_first_column]
        .iter()
        .map(|eval| CircleEvaluation::new(domain, to_bitreverse_eval_base_columns(eval)))
        .collect()
}

fn trace_steps_to_trace(trace: &PermCircuitTrace) -> [BaseColumn; N_TUPLE_ELM * 2] {
    trace
        .inner
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

    // Trace.
    let trace = gen_trace(log_n_rows, &circuit);
    let mut tree_builder = commitment_scheme.tree_builder();
    let base_trace_location = tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Draw permutation element
    let perm_element = PermElements::draw(channel);

    // Interaction trace.
    let trace = gen_interaction_trace(log_n_rows, &basic_trace, &perm_element);
    let mut tree_builder = commitment_scheme.tree_builder();
    let interaction_trace_location = tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    // Constant trace. This is a separate interaction because we send the commitment for
    // the constant trace to the verifier.
    let trace = gen_constant_trace(log_n_rows);
    let mut tree_builder = commitment_scheme.tree_builder();
    let constant_trace_location = tree_builder.extend_evals(trace);
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
    // Trace columns.
    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    // Interaction columns.
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    // Constant columns.
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

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
        inner: Array2D::from_iter_row_major(row_major, n_rows, N_TUPLE_ELM * 2).unwrap(),
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
        inner: Array2D::from_iter_row_major(row_major, 1 << log_n_rows, N_TUPLE_ELM * 2).unwrap(),
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
