<p align="center">
  <p align="center">
   <img width="150" height="150" src="assets/logo.png" alt="Logo">
  </p>
	<h1 align="center"><b>The Nexus zkVM</b></h1>
	<p align="center">
		The zero-knowledge virtual machine.
    <br />
    <a href="https://nexus.xyz"><strong>nexus.xyz »</strong></a>
  </p>
</p>

<p align="center">
  <a href="https://x.com/NexusLabsHQ">
    <img src="https://img.shields.io/badge/Twitter-black?logo=x&logoColor=white" />
  </a>
  <img src="https://img.shields.io/static/v1?label=Stage&message=Alpha&color=2BB4AB" />
  <br />
</p>

# The Nexus zkVM

The Nexus zkVM is a machine designed to prove abitrary computations. It allows anyone to generate zero-knowledge proofs for programs written in Rust. It is designed for simplicity, safety and performance.

## The Nexus Virtual Machine

The Nexus zkVM proves executions against any CPU architecture (e.g. RISC-V, Wasm, EVM, etc.) through compilation against the Nexus Virtual Machine, a minimal CPU architecture designed to deliver maximum prover efficiency.

## Design Principles

The Nexus zkVM is designed with the following principles:
- Simplicity:
  - Generating and verifying zero-knowledge proofs should be as easy as `nexus prove` and `nexus verify`.
- Universality:
  - The zkVM can prove *any* computation, for any programming language (e.g. Rust, C++, Go), any machine architecture (e.g. RISC-V, Wasm, EVM), and any circuit arithmetization (e.g. R1CS, Plonkish, AIR).
- Incrementality:
  - The zkVM has no bounds on the size of the programs it can prove. Further, the proofs themselves are updatable.
- Ultra-high Performance:
  - The zkVM is designed to be massively-parallelizable, and is currently designed only to be practical for really large programs (> 1B CPU cycles).
- Cryptography-Opinionated:
  - The Nexus team makes deliberate and precise choices in the cryptography behind the zkVM prover, elliptic curves, proof systems, compression sequence, parallelization strategy, security properties, parameters, etc. to ensure maximum performance and security to developers.
- Extensibility and modularity:
  - The zkVM is designed to enrich the open-source community and be developer-first to ensure extensibility: it can easily be extended with custom instructions (e.g. SHA-256), new compilation toolchains, and can be adapted to prove new programming languages and CPU architectures.

## Quick Start

### 1. Install the Nexus zkVM

First install Rust: [bit.ly/start-rust](https://bit.ly/start-rust).

Then build and install the Nexus zkVM:

```shell
git clone https://github.com/nexus-xyz/nexus-zkvm
cd nexus-zkvm
cargo install --path .
```

This will generate the executable `~/.cargo/bin/nexus`.

Now you can use the Nexus zkVM:

```shell
cargo nexus --help
```

### 3. Create a new Nexus project

```shell
cargo nexus new nexus-project
```

This will create a directory with the following structure:

```shell
./nexus-project
├── Cargo.lock
├── Cargo.toml
└── src
    └── main.rs
```

### 4. Prove your code on the Nexus zkVM

Generate a zero-knowledge proof for your Rust program using the Nexus zkVM:

```shell
cargo nexus prove
```

### 5. Verify your proof

```shell
cargo nexus verify
```

---

## Example programs

TODO

## Developing

### Run all the zkVM tests

```shell
cargo test -r
```

### Benchmark the zkVM

```shell
cargo bench
```

### Profile the zkVM

TODO

## Spin up a Nexus prover network

```shell
cargo nexus network start --coordinator
```

```shell
cargo nexus network start --node -l 127.0.0.1:0
```

### Submit proofs against your local network

```shell
cargo nexus prove --network=localhost
```

### Submit proofs against the Nexus network

```shell
cargo nexus prove --network

Connected to https://cloud.nexus.xyz/
```
