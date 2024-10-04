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
and native compilation support, check out our [documentation](docs.nexus.xyz).
