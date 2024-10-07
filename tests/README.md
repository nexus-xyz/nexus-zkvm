# Integration tests
Run `cargo test --package testing-framework` to run the integration tests.

# Overview
- The current implementation of integration tests involves compiling a rust program with a dependency to `nexus-rt` to an elf file, which is then parsed as a Nexus VM instance and emulated. 
- Future implementations will also produce proofs of the emulated traces.
