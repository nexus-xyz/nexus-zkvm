use std::time::Instant;

use clap::Parser;
use nexus_vm_prover::{types::BooleanValue, utils};
use num_traits::{One as _, Zero as _};
use stwo_prover::{
    constraint_framework::{
        assert_constraints, EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    },
    core::{
        air::Component as _,
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        fields::m31::BaseField,
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig},
        poly::{
            circle::{CanonicCoset, CircleEvaluation, PolyOps as _},
            BitReversedOrder,
        },
        prover::{prove, verify},
        vcs::blake2_merkle::Blake2sMerkleChannel,
        ColumnVec,
    },
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "5", value_parser = clap::value_parser!(u32).range(5..=28))]
    pub rows_log: u32,

    #[arg(short, long, default_value = "1")]
    pub seed: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Fib {
    rows: usize,
    rows_log2: u32,
}

fn main() {
    let cli = Cli::parse();

    // setup trace

    let seed = BaseField::reduce(cli.seed);
    let fib = Fib::new(cli.rows_log);
    let main_trace = fib.main_trace(seed);
    let aux_trace = fib.aux_trace();

    // setup protocol

    let config = PcsConfig::default();
    let coset = CanonicCoset::new(cli.rows_log + 1 + config.fri_config.log_blowup_factor)
        .circle_domain()
        .half_coset;
    let twiddles = SimdBackend::precompute_twiddles(coset);
    let allocator = &mut TraceLocationAllocator::default();
    let component = FrameworkComponent::new(allocator, fib);

    let prover_channel = &mut Blake2sChannel::default();
    let prover_commitment_scheme =
        &mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

    let verifier_channel = &mut Blake2sChannel::default();
    let verifier_commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let verifier_component_sizes = component.trace_log_degree_bounds();

    // commit traces

    let commit_traces_time = Instant::now();

    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_trace);
    tree_builder.commit(prover_channel);

    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(aux_trace);
    tree_builder.commit(prover_channel);

    let commit_traces_time = Instant::now() - commit_traces_time;

    // Sanity check

    let traces = prover_commitment_scheme
        .trees
        .as_ref()
        .map(|t| t.polynomials.to_vec());

    assert_constraints(&traces, CanonicCoset::new(cli.rows_log), |evaluator| {
        Fib::new(cli.rows_log).evaluate(evaluator);
    });

    // prove statements

    let prove_time = Instant::now();

    let proof =
        prove(&[&component], prover_channel, prover_commitment_scheme).expect("failed to prove");

    let prove_time = Instant::now() - prove_time;
    let serialized_proof = bincode::serialize(&proof).expect("failed to serialize proof");

    // verify proof

    let verify_time = Instant::now();

    for i in 0..verifier_component_sizes.len() {
        verifier_commitment_scheme.commit(
            proof.commitments[i],
            &verifier_component_sizes[i],
            verifier_channel,
        );
    }

    verify(
        &[&component],
        verifier_channel,
        verifier_commitment_scheme,
        proof,
    )
    .expect("proof verification failed");

    let verify_time = Instant::now() - verify_time;

    println!("{: <20}: {: >30}", "Rows", fib.rows);
    println!(
        "{: <20}: {: >30}",
        "Trace commitment",
        humantime::format_duration(commit_traces_time).to_string()
    );
    println!(
        "{: <20}: {: >30}",
        "Prove statements",
        humantime::format_duration(prove_time).to_string()
    );
    println!(
        "{: <20}: {: >30}",
        "Verify proof",
        humantime::format_duration(verify_time).to_string()
    );
    println!(
        "{: <20}: {: >30}",
        "Proof size",
        format!(
            "{:#}",
            byte_unit::Byte::from_u64(serialized_proof.len() as u64)
        )
    );
}

impl Fib {
    pub const fn new(rows_log2: u32) -> Self {
        Self {
            rows: 1 << rows_log2 as usize,
            rows_log2,
        }
    }

    pub fn main_trace(
        &self,
        seed: BaseField,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_trace(
            [self.rows_log2, self.rows_log2],
            |cols, seed| {
                let (a, b) = cols.split_at_mut(1);

                let a = &mut a[0];
                let b = &mut b[0];

                // initialize row 0
                a[0] = seed;
                b[0] = seed;

                // execute the fibonacci program
                for i in 1..a.len() {
                    b[i] = a[i - 1] + b[i - 1];
                    a[i] = b[i - 1];
                }
            },
            seed,
        )
    }

    pub fn aux_trace(
        &self,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_trace(
            [self.rows_log2, self.rows_log2],
            |cols, _| {
                let zero = BaseField::zero();
                let one = BaseField::one();
                let (is_first, is_first_neg) = cols.split_at_mut(1);

                let is_first = &mut is_first[0];
                let is_first_neg = &mut is_first_neg[0];

                // initialize row 0
                is_first[0] = one;
                is_first_neg[0] = zero;

                // execute the fibonacci program
                for i in 1..is_first.len() {
                    is_first[i] = zero;
                    is_first_neg[i] = one;
                }
            },
            (),
        )
    }
}

impl FrameworkEval for Fib {
    fn log_size(&self) -> u32 {
        self.rows_log2
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size() + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // The first argument of `next_interaction_mask` is the offset for the trace.
        //
        // The main trace will be `0`, and the aux trace will be `1`. More traces would further
        // increment this offset.
        //
        // The second argument is the values relative to the current row we want to fetch, being
        // `0` the current row. `-1` is the previous row, `1` is the next row.

        let a = eval.next_interaction_mask(0, [0, 1]);
        let b = eval.next_interaction_mask(0, [0, 1]);
        let is_first = eval.next_interaction_mask(1, [0, 1]);
        let is_first_neg = eval.next_interaction_mask(1, [0, 1]);

        // ----------------------------------------------------------------------------------------
        // Main trace
        // ----------------------------------------------------------------------------------------
        // Asserts the fibonacci program:
        //
        // b0 = a1
        // b1 = a0 + a1
        //
        // The next row `!is_first` will be `1` for every row, except the last. The last row is not
        // a valid fibonacci row, as the next row will be the wrapped table (hence, the initial
        // values).
        // ----------------------------------------------------------------------------------------
        eval.add_constraint(is_first_neg[1] * (b[0] - a[1]));
        eval.add_constraint(is_first_neg[1] * (b[1] - a[0] - a[1]));

        // ----------------------------------------------------------------------------------------
        // Aux trace
        // ----------------------------------------------------------------------------------------
        // The goal of this trace is to provide a column `is_first0` that is `1` if, and only if,
        // this is the first row.
        // ----------------------------------------------------------------------------------------

        // asserts the aux trace is boolean
        let is_first0 = BooleanValue::new(&mut eval, is_first[0]);
        let is_first0_neg = BooleanValue::new(&mut eval, is_first_neg[0]);

        // asserts `is_first0_neg = !is_first0`
        is_first0.neg(&mut eval, &is_first0_neg);

        // asserts `is_first0` is `1` only for the first row
        is_first0.is_first_row(&mut eval);

        eval
    }
}
