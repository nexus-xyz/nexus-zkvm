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

## Testing examples with private inputs

Some examples expect private inputs. An example of
programmatically invoking a program with a private input can be
found in `/core/examples/prover_run.rs`.
