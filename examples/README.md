# Nexus zkVM Examples

#### Fibonacci (prover)

In this example, we demonstrate the use of STWO to create a Fibonacci program that iterates for `n` times.

```
cargo run --release \
    -p nexus-examples \
    --bin fibonacci -- \
    -r 6
```

The argument supplied with `-r` is the `log2` of the total row count, which will generate a table containing `2^r` rows.
