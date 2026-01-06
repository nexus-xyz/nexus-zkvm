# Nexus SDK

The Nexus SDK provides simple, misuse-resistant programmatic use of the Nexus zkVM.

## Quick Start

### 1. Install the Nexus zkVM

First, install Rust: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

Next, install the RISC-V target:

```shell
$ rustup target add riscv32im-unknown-none-elf
```

Then, install the Nexus zkVM:

```shell
$ rustup run nightly-2025-05-09 cargo install --git https://github.com/nexus-xyz/nexus-zkvm cargo-nexus --tag 'v0.3.6'
```

And verify the installation:

```shell
$ rustup run nightly-2025-05-09 cargo nexus --help
```

This should print the available CLI commands. At present, the `cargo nexus` CLI is minimal, providing just a `cargo nexus host` command to setup an SDK based project.

### 2. Create a new Nexus host project

To use the zkVM programmatically, we need two programs: a _guest_ program that runs on the zkVM, and a _host_ program that operates the zkVM itself. Run:

```shell
$ rustup run nightly-2025-05-09 cargo nexus host nexus-host
```

This will create a new Rust project directory with the following structure:

```shell
./nexus-host
├── Cargo.lock
├── Cargo.toml
├── rust-toolchain.toml
└── src
    ├── main.rs
    └── guest
        ├── Cargo.toml
        ├── rust-toolchain.toml
        └── src
            └── main.rs
```

Here, `./src/main.rs` is our host program, while `./src/guest/src/main.rs` is our guest program.

As a slightly more interesting example than the default Hello, World! program, you can change the content of `./src/guest/src/main.rs` to:

```rust
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::println;

#[nexus_rt::main]
#[nexus_rt::public_input(x)]
fn main(x: u32, y: u32) -> u32 {
    println!("Read public input:  {}", x);
    println!("Read private input: {}", y);

    x * y
}
```

This guest program takes as input two integers, one public and one private, logs their values, and then returns their product.

Then, change the content of `./src/main.rs` to:

```rust
use nexus_sdk::{
    compile::{cargo::CargoPackager, Compile, Compiler},
    stwo::seq::Stwo,
    ByGuestCompilation, Local, Prover, Verifiable, Viewable,
};

const PACKAGE: &str = "guest";

fn main() {
    println!("Compiling guest program...");
    let mut prover_compiler = Compiler::<CargoPackager>::new(PACKAGE);
    let prover: Stwo<Local> =
        Stwo::compile(&mut prover_compiler).expect("failed to compile guest program");

    let elf = prover.elf.clone(); // save elf for use with test verification

    print!("Proving execution of vm... ");
    let (view, proof) = prover
        .prove_with_input::<u32, u32>(&3, &5)
        .expect("failed to prove program"); // x = 5, y = 3

    assert_eq!(view.exit_code().expect("failed to retrieve exit code"), 0);

    let output: u32 = view
        .public_output::<u32>()
        .expect("failed to retrieve public output");
    assert_eq!(output, 15); // z = 15

    println!("output is {}!", output);
    println!(
        ">>>>> Logging\n{}<<<<<",
        view.logs().expect("failed to retrieve debug logs").join("")
    );

    print!("Verifying execution...");
    proof
        .verify_expected::<u32, u32>(
            &5,   // x = 5
            0,    // exit code = 0
            &15,  // z = 15
            &elf, // expected elf (program binary)
            &[],  // no associated data,
        )
        .expect("failed to verify proof");

    println!("  Succeeded!");
}
```

This host program compiles the guest program and then invokes the resultant binary with public input `x = 5` and private input `y = 3`.

The zkVM will then run the guest program, return a view containing the output (`z = 15`) and logs, and produce a proof of its correct execution.

After the proving completes, the host program then reads the output out of the view, checks it and prints it along with any logs, and then verifies the proof.

### 3. Run your program

Next, we can run the host program (including executing and proving the guest program) with:

```bash
$ cargo run -r
```

You should see the host program print:

```
Proving execution of vm... output is 15!
>>>>> Logging
Read public input:  5
Read private input: 3
<<<<<
Verifying execution...  Succeeded!
```

To see more example of using the SDK, check out [the examples folder](./examples/).

### 4. Run in legacy mode

In addition the Stwo-based Nexus zkVM 3.0 prover, the SDK also supports a _legacy mode_ that uses the Nova, HyperNova, and (experimentally) Jolt-based Nexus zkVM 2.0 machine. This machine uses a different runtime and requires additional configuration on the host side due to the use of public parameters and reference strings.

To use the legacy mode, you must first activate the appropriate feature for the `nexus-sdk` dependency in the host program: `legacy-nova`, `legacy-hypernova`, or `legacy-jolt`. Examples of using legacy mode to prove [legacy guest programs](../examples/legacy) are provided in [the examples folder](./examples/).

To review the code used in the legacy mode, it corresponds to the [Nexus zkVM v0.2.4 release](https://github.com/nexus-xyz/nexus-zkvm/tree/releases/0.2.4).

## Learn More

See our zkVM documentation, including guides and walkthroughs, at [docs.nexus.xyz](https://docs.nexus.xyz/zkvm/index). Our SDK package documentation can be viewed at [sdk-docs.nexus.xyz](https://sdk-docs.nexus.xyz/doc/nexus_sdk/index.html).
