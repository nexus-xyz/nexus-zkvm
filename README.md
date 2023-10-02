# The Nexus zkVM

## Quick Start

Make sure you have a recent stable rust compiler with the RISC-V target.
The RISC-V target can be installed using `rustup`:

```sh
rustup target add riscv32i-unknown-none-elf
```

Install the Nexus tools to get access to the `cargo nexus`,
and the `nexus-run` commands.

```sh
cargo install --path tools
```

To start a new project use:

```sh
cargo nexus new
```

Note, you may get an authentication error. The current new command
will attempt to add a dependency on this git repo for `nexus-rt`.
Since this repo is private, you may need to tell cargo to use the
`git` command to fetch the repo rather than using the built-in
git library.
This can be done by setting a parameter in `.cargo/config`:

```toml
net.git-fetch-with-cli = true
```

Alternatively, you can configure your SSH keys with cargo.

Also note that if your new project will live in this repo, it
is best to change the `Cargo.toml` file to list a local path
to `runtime` rather than the default git repo.

If successful, you can run the new project binary with `cargo run`.

Proving programs can be done with either `msnova` or `prover`.
The first uses the Microsoft Nova implementation, and the second uses
the Nexus Nova implementation. For example:

```
cd msnova
cargo run -r riscv_elf_file
```

```
cd prover
# generate public parameters to file
cargo run -r -- gen

# prove using saves parameters
cargo run -r -- prove riscv_elf_file

# generate public parameter and prove
cargo run -r -- prove -g riscv_elf_file
```
