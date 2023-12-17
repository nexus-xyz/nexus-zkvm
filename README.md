<p align="center">
  <p align="center">
   <img width="150" height="150" src="assets/logo.png" alt="Logo">
  </p>
	<h1 align="center"><b>The Nexus zkVM</b></h1>
	<p align="center">
		The ultimate zero-knowledge virtual machine.
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

Proving programs can be done with either locally or using the Nexus network.
To prove using the nexus network, use the `prove` command.

```
cargo nexus prove       # prove debug build
cargo nexus prove -r    # prove release build
```

If your project contains multiple binaries, you may need to
specify the binary to use:

```
cargo nexus prove --bin name
```
You can check on the status of your proof, and download the result
using the `query` command:

```
cargo nexus query --hash e087116c0b13fb1a66af46d572b78e98b76c0bf814bd4f5df781469a3755fd33
```

If the proof is complete it will be saved to `nexus-proof.json`; this filename
can be changed on the command line (see -h for help).

You can check a proof using the `verify` command:

```
cargo nexus verify
```

You may need to specify the input files on the command line:

```
cargo nexus verify --public-params nexus-public.zst -f nexus-proof.json
```

Local proofs can be done using the `local-prove` command:

```
cargo nexus local-prove --bin example
```
