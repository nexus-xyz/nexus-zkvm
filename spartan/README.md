# Spartan: High-speed zkSNARKs without trusted setup

![Rust](https://github.com/microsoft/Spartan/workflows/Rust/badge.svg)
[![](https://img.shields.io/crates/v/spartan.svg)](<(https://crates.io/crates/spartan)>)

Spartan is a high-speed zero-knowledge proof system, a cryptographic primitive that enables a prover to prove a mathematical statement to a verifier without revealing anything besides the validity of the statement. This repository provides `libspartan,` a Rust library that implements a zero-knowledge succinct non-interactive argument of knowledge (zkSNARK), which is a type of zero-knowledge proof system with short proofs and fast verification times. The details of the Spartan proof system are described in our [paper](https://eprint.iacr.org/2019/550) published at [CRYPTO 2020](https://crypto.iacr.org/2020/). The security of the Spartan variant implemented in this library is based on the discrete logarithm problem in the random oracle model.

A simple example application is proving the knowledge of a secret s such that H(s) == d for a public d, where H is a cryptographic hash function (e.g., SHA-256, Keccak). A more complex application is a database-backed cloud service that produces proofs of correct state machine transitions for auditability. See this [paper](https://eprint.iacr.org/2020/758.pdf) for an overview and this [paper](https://eprint.iacr.org/2018/907.pdf) for details.

Note that this library has _not_ received a security review or audit.

## Highlights

We now highlight Spartan's distinctive features.

- **No "toxic" waste:** Spartan is a _transparent_ zkSNARK and does not require a trusted setup. So, it does not involve any trapdoors that must be kept secret or require a multi-party ceremony to produce public parameters.

- **General-purpose:** Spartan produces proofs for arbitrary NP statements. `libspartan` supports NP statements expressed as rank-1 constraint satisfiability (R1CS) instances, a popular language for which there exists efficient transformations and compiler toolchains from high-level programs of interest.

- **Sub-linear verification costs:** Spartan is the first transparent proof system with sub-linear verification costs for arbitrary NP statements (e.g., R1CS).

- **Standardized security:** Spartan's security relies on the hardness of computing discrete logarithms (a standard cryptographic assumption) in the random oracle model. `libspartan` uses `ristretto255`, a prime-order group abstraction atop `curve25519` (a high-speed elliptic curve). We use [`curve25519-dalek`](https://docs.rs/curve25519-dalek) for arithmetic over `ristretto255`.

- **State-of-the-art performance:**
  Among transparent SNARKs, Spartan offers the fastest prover with speedups of 36–152× depending on the baseline, produces proofs that are shorter by 1.2–416×, and incurs the lowest verification times with speedups of 3.6–1326×. The only exception is proof sizes under Bulletproofs, but Bulletproofs incurs slower verification both asymptotically and concretely. When compared to the state-of-the-art zkSNARK with trusted setup, Spartan’s prover is 2× faster for arbitrary R1CS instances and 16× faster for data-parallel workloads.

### Implementation details

`libspartan` uses [`merlin`](https://docs.rs/merlin/) to automate the Fiat-Shamir transform. We also introduce a new type called `RandomTape` that extends a `Transcript` in `merlin` to allow the prover's internal methods to produce private randomness using its private transcript without having to create `OsRng` objects throughout the code. An object of type `RandomTape` is initialized with a new random seed from `OsRng` for each proof produced by the library.

## Examples

To import `libspartan` into your Rust project, add the following dependency to `Cargo.toml`:

```text
spartan = "0.7.0"
```

The following example shows how to use `libspartan` to create and verify a SNARK proof.
Some of our public APIs' style is inspired by the underlying crates we use.

```rust
# extern crate libspartan;
# extern crate merlin;
# use libspartan::{Instance, SNARKGens, SNARK, polycommitments::{PolyCommitmentScheme, hyrax::Hyrax}};
# use merlin::Transcript;
# use ark_bls12_381::{G1Projective, Fr};
# use ark_std::{test_rng};
#
# fn main() {
    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;
    let num_non_zero_entries = 1024;

    // produce public parameters
    let min_num_vars = SNARKGens::<G1Projective, Hyrax<G1Projective>>::get_min_num_vars(num_cons, num_vars, num_inputs, num_non_zero_entries);
    // derive a SRS for the polynomial commitment scheme
    let SRS = Hyrax::<G1Projective>::setup(min_num_vars, b"example_SRS", &mut test_rng()).unwrap();
    let gens = SNARKGens::<G1Projective, Hyrax<G1Projective>>::new(&SRS, num_cons, num_vars, num_inputs, num_non_zero_entries);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(&inst, &comm, &decomm, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
      .verify(&comm, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
    println!("proof verification successful!");
# }
```

Here is another example to use the NIZK variant of the Spartan proof system:

```rust
# extern crate libspartan;
# extern crate merlin;
# use libspartan::{Instance, NIZKGens, NIZK};
# use merlin::Transcript;
# use ark_bls12_381::{G1Projective, Fr};
#
# fn main() {
    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;

    // produce public parameters
    let gens = NIZKGens::<G1Projective>::new(num_cons, num_vars, num_inputs);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::<Fr>::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
      .verify(&inst, &inputs, &mut verifier_transcript, &gens)
      .is_ok());
    println!("proof verification successful!");
# }
```

Finally, we provide an example that specifies a custom R1CS instance instead of using a synthetic instance

```rust
#![allow(non_snake_case)]
# extern crate libspartan;
# extern crate merlin;
# use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK, polycommitments::{PolyCommitmentScheme, hyrax::Hyrax}};
# use merlin::Transcript;
# use ark_std::test_rng;
# use ark_std::{One, Zero};
# use ark_std::{UniformRand};
# use ark_bls12_381::{Fr, G1Projective};
#
# fn main() {
  // produce a tiny instance
  let (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  ) = produce_tiny_r1cs();

  // produce public parameters
  # let min_num_vars = SNARKGens::<G1Projective, Hyrax<G1Projective>>::get_min_num_vars(num_cons, num_vars, num_inputs, num_non_zero_entries);
  // derive SRS for polynomial commitment scheme
  let SRS = Hyrax::<G1Projective>::setup(min_num_vars, b"example_SRS", &mut test_rng()).unwrap();
  let gens = SNARKGens::<G1Projective, Hyrax<G1Projective>>::new(&SRS, num_cons, num_vars, num_inputs, num_non_zero_entries);

  // create a commitment to the R1CS instance
  let (comm, decomm) = SNARK::<G1Projective, Hyrax<G1Projective>>::encode(&inst, &gens);

  // produce a proof of satisfiability
  let mut prover_transcript = Transcript::new(b"snark_example");
  let proof = SNARK::prove(
    &inst,
    &comm,
    &decomm,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
  );

  // verify the proof of satisfiability
  let mut verifier_transcript = Transcript::new(b"snark_example");
  assert!(proof
    .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok());
  println!("proof verification successful!");
# }

# fn produce_tiny_r1cs() -> (
#  usize,
#  usize,
#  usize,
#  usize,
#  Instance<Fr>,
#  VarsAssignment<Fr>,
#  InputsAssignment<Fr>,
# ) {
  // We will use the following example, but one could construct any R1CS instance.
  // Our R1CS instance is three constraints over five variables and two public inputs
  // (Z0 + Z1) * I0 - Z2 = 0
  // (Z0 + I1) * Z2 - Z3 = 0
  // Z4 * 1 - 0 = 0

  // parameters of the R1CS instance rounded to the nearest power of two
  let num_cons = 4;
  let num_vars = 5;
  let num_inputs = 2;
  let num_non_zero_entries = 5;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, Fr)> = Vec::new();
  let mut B: Vec<(usize, usize, Fr)> = Vec::new();
  let mut C: Vec<(usize, usize, Fr)> = Vec::new();

  // The constraint system is defined over a finite field, which in our case is
  // the scalar field of ristreeto255/curve25519 i.e., p =  2^{252}+27742317777372353535851937790883648493
  // To construct these matrices, we will use `curve25519-dalek` but one can use any other method.

  // a variable that holds a byte representation of 1
  let one = Fr::one();

  // R1CS is a set of three sparse matrices A B C, where is a row for every
  // constraint and a column for every entry in z = (vars, 1, inputs)
  // An R1CS instance is satisfiable iff:
  // Az \circ Bz = Cz, where z = (vars, 1, inputs)

  // constraint 0 entries in (A,B,C)
  // constraint 0 is (Z0 + Z1) * I0 - Z2 = 0.
  // We set 1 in matrix A for columns that correspond to Z0 and Z1
  // We set 1 in matrix B for column that corresponds to I0
  // We set 1 in matrix C for column that corresponds to Z2
  A.push((0, 0, one));
  A.push((0, 1, one));
  B.push((0, num_vars + 1, one));
  C.push((0, 2, one));

  // constraint 1 entries in (A,B,C)
  A.push((1, 0, one));
  A.push((1, num_vars + 2, one));
  B.push((1, 2, one));
  C.push((1, 3, one));

  // constraint 3 entries in (A,B,C)
  A.push((2, 4, one));
  B.push((2, num_vars, one));

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  // compute a satisfying assignment
  let mut prng = test_rng();
  let i0 = Fr::rand(&mut prng);
  let i1 = Fr::rand(&mut prng);
  let z0 = Fr::rand(&mut prng);
  let z1 = Fr::rand(&mut prng);
  let z2 = (z0 + z1) * i0; // constraint 0
  let z3 = (z0 + i1) * z2; // constraint 1
  let z4 = Fr::zero(); //constraint 2

  // create a VarsAssignment
  let mut vars = vec![Fr::zero(); num_vars];
  vars[0] = z0;
  vars[1] = z1;
  vars[2] = z2;
  vars[3] = z3;
  vars[4] = z4;
  let assignment_vars = VarsAssignment::new(&vars).unwrap();

  // create an InputsAssignment
  let mut inputs = vec![Fr::zero(); num_inputs];
  inputs[0] = i0;
  inputs[1] = i1;
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  // check if the instance we created is satisfiable
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert_eq!(res.unwrap(), true);

  (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  )
# }
```

For more examples, see [`examples/`](examples) directory in this repo.

## Building `libspartan`

Install [`rustup`](https://rustup.rs/)

Switch to nightly Rust using `rustup`:

```text
rustup default nightly
```

Clone the repository:

```text
git clone https://github.com/Microsoft/Spartan
cd Spartan
```

To build docs for public APIs of `libspartan`:

```text
cargo doc
```

To run tests:

```text
RUSTFLAGS="-C target_cpu=native" cargo test
```

To build `libspartan`:

```text
RUSTFLAGS="-C target_cpu=native" cargo build --release
```

> NOTE: We enable SIMD instructions in `curve25519-dalek` by default, so if it fails to build remove the "simd_backend" feature argument in `Cargo.toml`.

### Supported features

- `profile`: enables fine-grained profiling information (see below for its use)

## Performance

### End-to-end benchmarks

`libspartan` includes two benches: `benches/nizk.rs` and `benches/snark.rs`. If you report the performance of Spartan in a research paper, we recommend using these benches for higher accuracy instead of fine-grained profiling (listed below).

To run end-to-end benchmarks:

```text
RUSTFLAGS="-C target_cpu=native" cargo bench
```

### Fine-grained profiling

Build `libspartan` with `profile` feature enabled. It creates two profilers: `./target/release/snark` and `./target/release/nizk`.

These profilers report performance as depicted below (for varying R1CS instance sizes). The reported
performance is from running the profilers on a Microsoft Surface Laptop 3 on a single CPU core of Intel Core i7-1065G7 running Ubuntu 20.04 (atop WSL2 on Windows 10).
See Section 9 in our [paper](https://eprint.iacr.org/2019/550) to see how this compares with other zkSNARKs in the literature.

```text
$ ./target/release/snark
Profiler:: SNARK
  * number_of_constraints 1048576
  * number_of_variables 1048576
  * number_of_inputs 10
  * number_non-zero_entries_A 1048576
  * number_non-zero_entries_B 1048576
  * number_non-zero_entries_C 1048576
  * SNARK::encode
  * SNARK::encode 14.2644201s
  * SNARK::prove
    * R1CSProof::prove
      * polycommit
      * polycommit 2.7175848s
      * prove_sc_phase_one
      * prove_sc_phase_one 683.7481ms
      * prove_sc_phase_two
      * prove_sc_phase_two 846.1056ms
      * polyeval
      * polyeval 193.4216ms
    * R1CSProof::prove 4.4416193s
    * len_r1cs_sat_proof 47024
    * eval_sparse_polys
    * eval_sparse_polys 377.357ms
    * R1CSEvalProof::prove
      * commit_nondet_witness
      * commit_nondet_witness 14.4507331s
      * build_layered_network
      * build_layered_network 3.4360521s
      * evalproof_layered_network
        * len_product_layer_proof 64712
      * evalproof_layered_network 15.5708066s
    * R1CSEvalProof::prove 34.2930559s
    * len_r1cs_eval_proof 133720
  * SNARK::prove 39.1297568s
  * SNARK::proof_compressed_len 141768
  * SNARK::verify
    * verify_sat_proof
    * verify_sat_proof 20.0828ms
    * verify_eval_proof
      * verify_polyeval_proof
        * verify_prod_proof
        * verify_prod_proof 1.1847ms
        * verify_hash_proof
        * verify_hash_proof 81.06ms
      * verify_polyeval_proof 82.3583ms
    * verify_eval_proof 82.8937ms
  * SNARK::verify 103.0536ms
```

```text
$ ./target/release/nizk
Profiler:: NIZK
  * number_of_constraints 1048576
  * number_of_variables 1048576
  * number_of_inputs 10
  * number_non-zero_entries_A 1048576
  * number_non-zero_entries_B 1048576
  * number_non-zero_entries_C 1048576
  * NIZK::prove
    * R1CSProof::prove
      * polycommit
      * polycommit 2.7220635s
      * prove_sc_phase_one
      * prove_sc_phase_one 722.5487ms
      * prove_sc_phase_two
      * prove_sc_phase_two 862.6796ms
      * polyeval
      * polyeval 190.2233ms
    * R1CSProof::prove 4.4982305s
    * len_r1cs_sat_proof 47024
  * NIZK::prove 4.5139888s
  * NIZK::proof_compressed_len 48134
  * NIZK::verify
    * eval_sparse_polys
    * eval_sparse_polys 395.0847ms
    * verify_sat_proof
    * verify_sat_proof 19.286ms
  * NIZK::verify 414.5102ms
```

## LICENSE

See [LICENSE](./LICENSE)

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md)
