# Nexus zkVM Prover

This serves as the foundation of the zkVM, tasked with capturing and synthesizing the execution trace into a succinct, zero-knowledge proof.

## Examples

#### Fibonacci (prover)

In this example, we demonstrate the use of STWO to create a Fibonacci program that iterates for `n` times.

```
cargo run --release \
    -p nexus-vm-prover \
    --example fibonacci -- \
    -r 6
```

The argument supplied with `-r` is the `log2` of the total row count, which will generate a table containing `2^r` rows.

#### Permutation (prover)

In this example, we demonstrate the use of STWO to check many pairs of numbers are permutations.

```
cargo run --release \
    -p nexus-vm-prover \
    --example permutation -- \
    -r 10
```

The argument supplied with `-r` is the `log2` of the total row count, which will generate a table containing `2^r` rows.

#### Nanofibonacci (prover)

In this example, we compute the fibonacci numbers using a small machine that does different things according to the current program counter:

```
cargo run \
    -p nexus-vm-prover \
    --example nanofib -- --n-th 300 --rows-log2 11
```

The `--n-th` argument specifies which Fibonacci number is calculated. `--rows-log2` specifies the length of the computation trace.