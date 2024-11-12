// Nanofibonacci machine
// This is a simple example of the prover usage, aiming at a precursor of the
// microfibonacci architecture.

// Instruction fetching and parsing are complicated topics on their own,
// so we will skip them for now.

// The machine has 5 registers: R1, R2, R3, R4 and PC.
// Each register contains a M31 element.

// PC is the program counter. We skip the number R0 because it will be a special
// register in the future.

// The machine has no instructions. Therefore it's not a CPU. Nanofibonacci is
// just a machine, not an architecture yet.

// pc == 0 means { r3 <- r1 + r2; pc++; }
// pc == 1 means { r1 <- r2; pc++; }
// pc == 2 means { r2 <- r3; pc++; }
// pc == 3 means { r4 <- r4 - 1; pc++; }
// pc == 4 means { if r4 != 0 { pc <- 0; } else { pc++; } }
// pc == 5 means { /* Don't increment pc and stay there */}

// The machine is designed to calculate the Fibonacci sequence.
// The initial two elements are stored in R1 and R2.
// The initial value of R4 is the number of additions performed.
// Don't put 0 in R4.

use clap::{command, Parser};
use nexus_vm_prover::utils;
use num_traits::{zero, One, Zero};
use std::process::exit;
use stwo_prover::{
    constraint_framework::{
        assert_constraints, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    },
    core::{
        air::Component,
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        fields::m31::BaseField,
        pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig},
        poly::{
            circle::{CanonicCoset, CircleEvaluation, PolyOps},
            BitReversedOrder,
        },
        prover::{prove, verify},
        vcs::blake2_merkle::Blake2sMerkleChannel,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct Nanofib {
    n_rows_log2: u32,
    n_th: u32,
    expected: BaseField,
}

impl Nanofib {
    const N_COLUMNS: usize = 5
      + 3 * 6 // pc0 -- pc5 with aux
      + 3 // r4_isnotzero
      + 1 // is_pc_four = (one - pc_not4) * (one - is_last)
      ;
    fn new(n_rows_log2: u32, n_th: u32) -> Self {
        if n_th < 2 {
            eprintln!("The first two Fibonacci numbers are never computed.");
            exit(1);
        }
        if Self::expected_row_size(n_th) > 2u64.pow(n_rows_log2) {
            eprintln!("The number of trace rows is too small.");
            exit(1);
        }
        let expected = {
            let mut a = BaseField::zero();
            let mut b = BaseField::one();
            for _ in 0..n_th {
                let c = a + b;
                a = b;
                b = c;
            }
            a
        };
        Self {
            n_rows_log2,
            n_th,
            expected,
        }
    }
    fn expected_row_size(n_th: u32) -> u64 {
        n_th as u64 * 5 + 1
    }
    fn main_trace(&self) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_trace([self.n_rows_log2; Self::N_COLUMNS], |cols| {
            let [r1, r2, r3, r4, pc, pc_not0, pc_not0_a, pc_not0_b, pc_not1, pc_not1_a, pc_not1_b, pc_not2, pc_not2_a, pc_not2_b, pc_not3, pc_not3_a, pc_not3_b, pc_not4, pc_not4_a, pc_not4_b, pc_not5, pc_not5_a, pc_not5_b, r4_not0, r4_not0_a, r4_not0_b, is_pc_four] =
                cols
            else {
                assert!(
                    false,
                    "Wrong number of registers: forgot to add/remove a column?"
                );
                return; // never reached; silencing the compiler
            };
            let one: BaseField = 1.into();
            // Set initial value
            r2[0] = one;
            r4[0] = (self.n_th - 1).into();

            let n_rows = 2_usize.pow(self.n_rows_log2);
            let rows = 0..n_rows;
            for row in rows {
                // Some aux variables
                pc_not0[row] = if pc[row] == 0.into() { 0.into() } else { one };
                r4_not0[row] = if r4[row] == 0.into() { 0.into() } else { one };
                pc_not1[row] = if pc[row] == 1.into() { 0.into() } else { one };
                pc_not2[row] = if pc[row] == 2.into() { 0.into() } else { one };
                pc_not3[row] = if pc[row] == 3.into() { 0.into() } else { one };
                pc_not4[row] = if pc[row] == 4.into() { 0.into() } else { one };
                pc_not5[row] = if pc[row] == 5.into() { 0.into() } else { one };
                pc_not0_a[row] = if pc[row] == 0.into() {
                    one
                } else {
                    one / pc[row]
                };
                r4_not0_a[row] = if r4[row] == 0.into() {
                    one
                } else {
                    one / r4[row]
                };
                pc_not1_a[row] = if pc[row] == 1.into() {
                    one
                } else {
                    one / (pc[row] - one)
                };
                pc_not2_a[row] = if pc[row] == 2.into() {
                    one
                } else {
                    one / (pc[row] - BaseField::from(2))
                };
                pc_not3_a[row] = if pc[row] == 3.into() {
                    one
                } else {
                    one / (pc[row] - BaseField::from(3))
                };
                pc_not4_a[row] = if pc[row] == 4.into() {
                    one
                } else {
                    one / (pc[row] - BaseField::from(4))
                };
                pc_not5_a[row] = if pc[row] == 5.into() {
                    one
                } else {
                    one / (pc[row] - BaseField::from(5))
                };
                pc_not0_b[row] = if pc[row] == 0.into() { one } else { pc[row] };
                r4_not0_b[row] = if r4[row] == 0.into() { one } else { r4[row] };
                pc_not1_b[row] = if pc[row] == 1.into() {
                    one
                } else {
                    pc[row] - one
                };
                pc_not2_b[row] = if pc[row] == 2.into() {
                    one
                } else {
                    pc[row] - BaseField::from(2)
                };
                pc_not3_b[row] = if pc[row] == 3.into() {
                    one
                } else {
                    pc[row] - BaseField::from(3)
                };
                pc_not4_b[row] = if pc[row] == 4.into() {
                    one
                } else {
                    pc[row] - BaseField::from(4)
                };
                pc_not5_b[row] = if pc[row] == 5.into() {
                    one
                } else {
                    pc[row] - BaseField::from(5)
                };

                // Set aux variable for degree reduction
                is_pc_four[row] =
                    (one - pc_not4[row]) * (one - if row == n_rows - 1 { one } else { zero() });

                // Skip below in the last row because it will try to access over the end.
                if row == n_rows - 1 {
                    continue;
                }
                // By default the next row is the same as the current row
                r1[row + 1] = r1[row];
                r2[row + 1] = r2[row];
                r3[row + 1] = r3[row];
                r4[row + 1] = r4[row];
                pc[row + 1] = pc[row] + one;
                // With the following exceptions
                if pc[row] == 0.into() {
                    // pc == 0 means { r3 <- r1 + r2; pc++; }
                    r3[row + 1] = r1[row] + r2[row];
                } else if pc[row] == 1.into() {
                    // pc == 1 means { r1 <- r2; pc++; }
                    r1[row + 1] = r2[row];
                } else if pc[row] == 2.into() {
                    // pc == 2 means { r2 <- r3; pc++; }
                    r2[row + 1] = r3[row];
                } else if pc[row] == 3.into() {
                    // pc == 3 means { r4 <- r4 - 1; pc++; }
                    r4[row + 1] = r4[row] - one;
                } else if pc[row] == 4.into() {
                    // pc == 4 means { if r4 != 0 { pc <- 0; } else { pc++; } }
                    if r4[row] != 0.into() {
                        pc[row + 1] = 0.into();
                    }
                } else if pc[row] == 5.into() {
                    // pc == 5 means { /* Don't increment pc and stay there */}
                    pc[row + 1] = pc[row];
                } else {
                    panic!("Invalid pc value");
                }
            }
            debug_assert_eq!(r3[2_usize.pow(self.n_rows_log2) - 1], self.expected);
        })
    }
    fn constant_trace(&self) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        utils::generate_trace([self.n_rows_log2; 1], |cols| {
            cols[0][0] = 1.into(); // is_first
        })
    }
}

impl FrameworkEval for Nanofib {
    fn log_size(&self) -> u32 {
        self.n_rows_log2
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size() + 1 // Unsure.
    }
    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let [r1, r1_next] = eval.next_interaction_mask(0, [0, 1]);
        let [r2, r2_next] = eval.next_interaction_mask(0, [0, 1]);
        let [r3, r3_next] = eval.next_interaction_mask(0, [0, 1]);
        let [r4, r4_next] = eval.next_interaction_mask(0, [0, 1]);
        let [pc, pc_next] = eval.next_interaction_mask(0, [0, 1]);
        let pc_not0 = eval.next_trace_mask();
        let pc_not0_a = eval.next_trace_mask();
        let pc_not0_b = eval.next_trace_mask();
        let pc_not1 = eval.next_trace_mask();
        let pc_not1_a = eval.next_trace_mask();
        let pc_not1_b = eval.next_trace_mask();
        let pc_not2 = eval.next_trace_mask();
        let pc_not2_a = eval.next_trace_mask();
        let pc_not2_b = eval.next_trace_mask();
        let pc_not3 = eval.next_trace_mask();
        let pc_not3_a = eval.next_trace_mask();
        let pc_not3_b = eval.next_trace_mask();
        let pc_not4 = eval.next_trace_mask();
        let pc_not4_a = eval.next_trace_mask();
        let pc_not4_b = eval.next_trace_mask();
        let pc_not5 = eval.next_trace_mask();
        let pc_not5_a = eval.next_trace_mask();
        let pc_not5_b = eval.next_trace_mask();
        let r4_not0 = eval.next_trace_mask();
        let r4_not0_a = eval.next_trace_mask();
        let r4_not0_b = eval.next_trace_mask();
        let is_pc_four = eval.next_trace_mask();
        let [is_first, is_last] = eval.next_interaction_mask(1, [0, 1]);
        let one = E::F::one();

        // Check aux columns
        eval.add_constraint(pc.clone() * pc_not0_a.clone() - pc_not0.clone());
        eval.add_constraint(r4.clone() * r4_not0_a.clone() - r4_not0.clone());
        eval.add_constraint((pc.clone() - one.clone()) * pc_not1_a.clone() - pc_not1.clone());
        eval.add_constraint(
            (pc.clone() - E::F::from(2.into())) * pc_not2_a.clone() - pc_not2.clone(),
        );
        eval.add_constraint(
            (pc.clone() - E::F::from(3.into())) * pc_not3_a.clone() - pc_not3.clone(),
        );
        eval.add_constraint(
            (pc.clone() - E::F::from(4.into())) * pc_not4_a.clone() - pc_not4.clone(),
        );
        eval.add_constraint(
            (pc.clone() - E::F::from(5.into())) * pc_not5_a.clone() - pc_not5.clone(),
        );
        eval.add_constraint(r4_not0_a.clone() * r4_not0_b.clone() - one.clone());
        eval.add_constraint(pc_not0_a.clone() * pc_not0_b.clone() - one.clone());
        eval.add_constraint(pc_not1_a.clone() * pc_not1_b.clone() - one.clone());
        eval.add_constraint(pc_not2_a.clone() * pc_not2_b.clone() - one.clone());
        eval.add_constraint(pc_not3_a.clone() * pc_not3_b.clone() - one.clone());
        eval.add_constraint(pc_not4_a.clone() * pc_not4_b.clone() - one.clone());
        eval.add_constraint(pc_not5_a.clone() * pc_not5_b.clone() - one.clone());
        eval.add_constraint(r4_not0.clone() * (one.clone() - r4_not0.clone()));
        eval.add_constraint(pc_not0.clone() * (one.clone() - pc_not0.clone()));
        eval.add_constraint(pc_not1.clone() * (one.clone() - pc_not1.clone()));
        eval.add_constraint(pc_not2.clone() * (one.clone() - pc_not2.clone()));
        eval.add_constraint(pc_not3.clone() * (one.clone() - pc_not3.clone()));
        eval.add_constraint(pc_not4.clone() * (one.clone() - pc_not4.clone()));
        eval.add_constraint(pc_not5.clone() * (one.clone() - pc_not5.clone()));

        // Check initial values
        eval.add_constraint(is_first.clone() * r1.clone());
        eval.add_constraint(is_first.clone() * (r2.clone() - one.clone()));
        eval.add_constraint(is_first.clone() * r3.clone());
        eval.add_constraint(is_first.clone() * (r4.clone() - E::F::from((self.n_th - 1).into())));
        eval.add_constraint(is_first * pc.clone());

        // Check transition for pc == 0
        let is_pc_zero = (one.clone() - pc_not0) * (one.clone() - is_last.clone());
        eval.add_constraint(is_pc_zero.clone() * (r1_next.clone() - r1.clone()));
        eval.add_constraint(is_pc_zero.clone() * (r2_next.clone() - r2.clone()));
        eval.add_constraint(is_pc_zero.clone() * (r3_next.clone() - (r1.clone() + r2.clone())));
        eval.add_constraint(is_pc_zero.clone() * (r4_next.clone() - r4.clone()));
        eval.add_constraint(is_pc_zero.clone() * (pc_next.clone() - (pc.clone() + one.clone())));

        // Check transition for pc == 1
        let is_pc_one = (one.clone() - pc_not1) * (one.clone() - is_last.clone());
        eval.add_constraint(is_pc_one.clone() * (r1_next.clone() - r2.clone()));
        eval.add_constraint(is_pc_one.clone() * (r2_next.clone() - r2.clone()));
        eval.add_constraint(is_pc_one.clone().clone().clone() * (r3_next.clone() - r3.clone()));
        eval.add_constraint(is_pc_one.clone().clone() * (r4_next.clone() - r4.clone()));
        eval.add_constraint(is_pc_one * (pc_next.clone() - (pc.clone() + one.clone())));

        // Check transition for pc == 2
        let is_pc_two = (one.clone() - pc_not2) * (one.clone() - is_last.clone());
        eval.add_constraint(is_pc_two.clone() * (r1_next.clone() - r1.clone()));
        eval.add_constraint(is_pc_two.clone() * (r2_next.clone() - r3.clone()));
        eval.add_constraint(is_pc_two.clone() * (r3_next.clone() - r3.clone()));
        eval.add_constraint(is_pc_two.clone() * (r4_next.clone() - r4.clone()));
        eval.add_constraint(is_pc_two * (pc_next.clone() - (pc.clone() + one.clone())));

        // Check transition for pc == 3
        let is_pc_three = (one.clone() - pc_not3) * (one.clone() - is_last.clone());
        eval.add_constraint(is_pc_three.clone() * (r1_next.clone() - r1.clone()));
        eval.add_constraint(is_pc_three.clone() * (r2_next.clone() - r2.clone()));
        eval.add_constraint(is_pc_three.clone() * (r3_next.clone() - r3.clone()));
        eval.add_constraint(is_pc_three.clone() * (r4_next.clone() - (r4.clone() - one.clone())));
        eval.add_constraint(is_pc_three * (pc_next.clone() - (pc.clone() + one.clone())));

        // Check transition for pc == 4
        eval.add_constraint(is_pc_four.clone() * (r1_next.clone() - r1.clone()));
        eval.add_constraint(is_pc_four.clone() * (r2_next.clone() - r2.clone()));
        eval.add_constraint(is_pc_four.clone() * (r3_next.clone() - r3.clone()));
        eval.add_constraint(is_pc_four.clone() * (r4_next.clone() - r4.clone()));
        eval.add_constraint(is_pc_four.clone() * r4_not0.clone() * pc_next.clone());
        eval.add_constraint(
            is_pc_four * (one.clone() - r4_not0) * (pc_next.clone() - (pc.clone() + one.clone())),
        );

        // Check transition for pc == 5
        let is_pc_five = (one.clone() - pc_not5) * (one - is_last.clone());
        eval.add_constraint(is_pc_five.clone() * (r1_next - r1));
        eval.add_constraint(is_pc_five.clone().clone() * (r2_next - r2));
        eval.add_constraint(is_pc_five.clone() * (r3_next - r3.clone()));
        eval.add_constraint(is_pc_five.clone() * (r4_next - r4));
        eval.add_constraint(is_pc_five * (pc_next - pc));

        // Check final result
        eval.add_constraint(is_last * (r3 - E::F::from(self.expected)));

        eval
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(
        short,
        long,
        default_value = "300",
        help = "Compute ?-th Fibonacci number"
    )]
    pub n_th: u32,

    #[arg(short, long, default_value = "11", help = "Number of trace rows in log2", value_parser = clap::value_parser!(u32).range(5..=28))]
    pub rows_log2: u32,
}

fn main() {
    let cli = Cli::parse();
    let nanofib = Nanofib::new(cli.rows_log2, cli.n_th);
    let config = PcsConfig::default();
    let coset = CanonicCoset::new(cli.rows_log2 + 1 + config.fri_config.log_blowup_factor)
        .circle_domain()
        .half_coset;
    let twiddles = SimdBackend::precompute_twiddles(coset);
    let allocator = &mut TraceLocationAllocator::default();
    let component = FrameworkComponent::new(allocator, nanofib);
    let prover_channel = &mut Blake2sChannel::default();
    let prover_commitment_scheme =
        &mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

    let main_trace = nanofib.main_trace();
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_trace);
    tree_builder.commit(prover_channel);

    let constant_trace = nanofib.constant_trace();
    let mut tree_builder = prover_commitment_scheme.tree_builder();
    tree_builder.extend_evals(constant_trace);
    tree_builder.commit(prover_channel);

    // Sanity check

    let traces = prover_commitment_scheme
        .trees
        .as_ref()
        .map(|t| t.polynomials.to_vec());

    assert_constraints(&traces, CanonicCoset::new(cli.rows_log2), |evaluator| {
        nanofib.evaluate(evaluator);
    });

    let proof =
        prove(&[&component], prover_channel, prover_commitment_scheme).expect("failed to prove");

    // verifier
    let verifier_channel = &mut Blake2sChannel::default();
    let verifier_commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let verifier_component_sizes = component.trace_log_degree_bounds();

    for i in 0..2 {
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

    println!(
        "nanofibonacci proved and verified {}th fibonatti numberi {:?}",
        cli.n_th, nanofib.expected
    );
}
