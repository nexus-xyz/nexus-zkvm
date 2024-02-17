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

<div align="center">
    <a href="https://t.me/nexus_zkvm">
        <img src="https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https%3A%2F%2Fmogyo.ro%2Fquart-apis%2Ftgmembercount%3Fchat_id%3Dnexus_zkvm"/>
    </a>
    <a href="https://twitter.com/NexusLabsHQ">
        <img src="https://img.shields.io/badge/Twitter-black?logo=x&logoColor=white"/>
    </a>
    <a href="https://nexus.xyz">
        <img src="https://img.shields.io/static/v1?label=Stage&message=Alpha&color=2BB4AB"/>
    </a>
</div>

# The Nexus zkVM

The Nexus zkVM is a modular, extensible, open-source, and massively-parallelized zkVM, designed to run at *a trillion CPU cycles proved per second* given enough machine power.


## Quick Start

### 1. Install the Nexus zkVM

First, install Rust: [bit.ly/start-rust](https://bit.ly/start-rust).

Second, install the RISC-V

Then, install the Nexus zkVM:

```shell
cargo install --git https://github.com/nexus-xyz/nexus-zkvm nexus-tools
```

Verify the installation:

```shell
cargo nexus --version
```

### 2. Create a new Nexus project

```shell
cargo nexus new nexus-project
```

This will create a new Rust project directory with the following structure:

```shell
./nexus-project
├── Cargo.lock
├── Cargo.toml
└── src
    └── main.rs
```

And an example zkVM Rust program in `./src/main.rs`:

```rust
#![no_std]
#![no_main]

fn fib(n: u32) -> u32 {
    match n {
        0 => 1,
        1 => 1,
        _ => fib(n - 1) + fib(n - 2),
    }
}

#[nexus::main]
fn main() {
    let n = 7;
    let result = fib(n);
    assert_eq!(result, 13);
}
```

### 3. Prove your program

Generate a zero-knowledge proof for your Rust program using the Nexus zkVM.

```shell
cargo nexus prove
```

This will generate a proof, and store it in `./proof.json`.

### 4. Verify your proof

Finally, load and verify the proof:

```shell
cargo nexus verify
```

## Learn More

Run `cargo nexus --help` to see all the available commands:

```shell
Usage: cargo nexus <COMMAND>

Commands:
  new      Create a new Nexus package at <path>
  run      Run a binary with the Nexus VM
  prove    Compute proof of program execution
  request  Request proof status from the network; download it if it's finished
  verify   Verify the proof
  pp       Nova public parameters management
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```
