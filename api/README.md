# Nexus API

This is a **low-level, unstable** API for programmatically accessing the Nexus VM and provers.

The roadmap is for it to be supplanted by a more strategically designed and consistent Nexus SDK. The API will likely shift as part of the SDK development effort.

The API is relatively self-documenting, see `./src/lib.rs`. Examples of using the API are given in `./examples`. The examples can be run with, for instance:

```sh
nexus-zkvm/examples$ cargo build -r
nexus-zkvm/api$ cargo run -r --example prover_run
```
