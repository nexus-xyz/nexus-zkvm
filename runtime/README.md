# Nexus Runtime

This crate contains the Nexus Runtime for RISC-V.  The runtime
includes basic startup code, a memory allocator, and macros for
accessing VM built-ins, such as program i/o and debug printing.

## Getting Started

First, you will need a rust compiler with the RISC-V target
installed.  If you do no have the RISC-V target installed,
you can install it with `rustup`:

```
rustup target add riscv32im-unknown-none-elf
```

Once your compiler is setup, the easiest way to start a new
project is to install the `cargo-nexus` crate, and use the
`cargo nexus new` command. You can also setup your new
project manually as described below.

To start, you will need to create a new project and add the
`nexus-rt` crate as a dependency:

```
cargo new myproject
cd myproject
cargo add nexus-rt
```

Next, for convenience, you can set the default target and
linker flags for the project in the `.cargo/config.toml` file
under the project directory. The contents of the file should
be:

```
[build]
target = "riscv32im-unknown-none-elf"

[target.riscv32im-unknown-none-elf]
rustflags = [
  "-C", "link-arg=-Tlinker-scripts/default.x",
]
```

The `build` section configures the default target to RISC-V
(installed above). The `target` section sets a command line
option which will include the `default.x` linker script
(contained in this repo) in the build process. This linker
script lays out the code and data of your program in a
simple way to make proving more efficient.

Finally, a minimal `main.rs` file may look like:

```rust
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[nexus_rt::main]
fn main() {}
```
The first two lines declare that our program will not link
against the `std` crate, and that we do not want the
compiler to emit the standard start-up code to process
command-line arguments and call `main`. The Nexus runtime
has a minimal start-up process and will call your entry
function directly. The fourth line brings the nexux-rt
`entry` macro into scope. This macro is used to mark the
`main` function as the starting point of the program.

To see more, such as how to introduce program i/o, precompiles,
and native compilation support, check out our [documentation](https://docs.nexus.xyz/zkvm/index).

## Crate Overview
#### Execution flow
- When a guest program is connected to the nexus runtime (by using the `#[nexus_rt::main]` macro), `asm.S` serves as the entry point, and will be the first instructions executed before moving on to the main rust function (via `start_rust` in `runtime.rs`).

#### Guest I/O
- All guest program I/O is handled at the RISC-V level with custom instructions. To see the definitions, refer to the associated macros in `src/lib.rs`.
- The addresses 0x80 and 0x84 will be prefilled with the start locations of input and output memory. From the runtime's perspective, reading an input only requires the index within the input to fetch from, without needing knowledge of where the input is located relative to the rest of the memory space. The same is true for outputs.
- When a program terminates, it will write the exit code to the end of the public output.

#### Memory
- The memory starting memory layout is specified by the linker script at `linker-scripts/default.x`.
- All memory allocations are handled by `alloc.rs`. In the future there may be a deallocator if the extra instructions required to implement it are outweighed by the space saved in terms of impact on prover performance.

#### Runtime macros
- `#[nexus_rt::main]` transforms the main body of a rust function to make the development process simpler and more intuitive. In this way, at surface level the main function will take inputs and return outputs as defined in the function signature (Ex: `fn main(x: u32) -> u32`). Under the hood, the guest program I/O memory interactions will happen via `read_public_input`, `read_private_input`, and `write_public_output` in `src/io.rs`.
- By default all I/O will be treated as public I/O. To create a private input `x`, define the variable in the main function signature, and use the macro `[nexus_rt::private_input(x)]`.
- The guest program development workflow allows for simultaneous multi-target compatibility. In order for this to work, every input and output variable must have a corresponding native handler (since native running has no concept of guest program memory). The macros for this are `[nexus_rt::custom_input]` and `[nexus_rt::custom_output]`.
- All of these definitions can be found in `macros/`. For additional examples and understanding, refer to `macros/macro_expansion_tests/tests`. Note that macros expand differently depending on the target (native vs RISC-V).
