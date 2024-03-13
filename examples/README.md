# Nexus VM Example Programs

This repository contains a set of Nexus VM example programs.
The default binary (`src/main.rs`), is a basic "hello world"
program. More complex programs can be found in `src/bin`.

## Using nexus-rt

Programs in this repository are built against `nexus-rt`, a
minimal RISC-V runtime for the nexus VM. After building the
examples, you can run them using the `nexus-run` tool, which is
configured as the default for cargo in this crate:

```sh
cargo run -r --bin example
```

## Proving program execution

### Using CLI

Similar to the quick guide, make sure to have the CLI tooling installed:
```sh
# from the root of the workspace
cargo install --path tools
```
And prove any example program from this crate
```sh
cd examples
cargo nexus prove --bin=fact
cargo nexus verify
```

### Using the prover API

An example script can be found [here](../prover/examples/prove.rs). Before running it, compile the program
```sh
cd examples
cargo build --release --bin=fact # if you change it, don't forget to update prove.rs as well
```

Prove and verify with the script:
```sh
cd prover
cargo run --release --example prove
```

> NOTE: the prover API is not stable and will very likely change in the future.
