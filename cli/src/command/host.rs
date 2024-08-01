use std::{fs, io::Write, path::PathBuf};

use anyhow::Context;
use clap::Args;

use crate::utils::cargo;

#[derive(Debug, Args)]
pub struct HostArgs {
    #[arg(name = "path")]
    pub path: PathBuf,
}

pub fn handle_command(args: HostArgs) -> anyhow::Result<()> {
    let path = args.path;

    setup_crate(path)
}

fn setup_crate(host_path: PathBuf) -> anyhow::Result<()> {
    let host_str = host_path
        .to_str()
        .context("path is not a valid UTF-8 string")?;

    let guest_path = host_path.join("src").join("guest");
    let guest_str = guest_path.to_str().unwrap();

    // run cargo to setup project
    cargo(None, ["new", host_str])?;
    cargo(
        Some(&host_path),
        [
            "add",
            "--git",
            "https://github.com/nexus-xyz/nexus-zkvm.git",
            "--tag",
            "0.2.1",
            "nexus-sdk",
        ],
    )?;

    let mut fp1 = fs::OpenOptions::new()
        .append(true)
        .open(host_path.join("Cargo.toml"))?;

    writeln!(
        fp1,
        concat!(
            "\n",
            "[workspace]\n",
            "members = [\n",
            "    \"src/guest\"\n",
            "]\n\n",
            "# Generated by cargo-nexus, do not remove!\n",
            "#\n",
            "# This profile is used for generating proofs, as Nexus VM support for compiler optimizations is still under development.\n",

            // https://doc.rust-lang.org/1.58.1/cargo/reference/overriding-dependencies.html#working-with-an-unpublished-minor-version
            "# These patches are required for some of the underlying cryptography libraries used by Nexus.\n",
            "[patch.crates-io]\n",
            "ark-crypto-primitives = {{ git = \"https://github.com/arkworks-rs/crypto-primitives/\", rev = \"d27a5c8\" }}\n",
            "ark-r1cs-std = {{ git = \"https://github.com/arkworks-rs/r1cs-std/\", rev = \"2ca3bd7\" }}\n",
            "ark-ff = {{ git = \"https://github.com/arkworks-rs/algebra/\", rev = \"2a80c54\" }}\n",
            "ark-ec = {{ git = \"https://github.com/arkworks-rs/algebra/\", rev = \"2a80c54\" }}\n",
            "ark-serialize = {{ git = \"https://github.com/arkworks-rs/algebra/\", rev = \"2a80c54\" }}\n",
            "ark-poly = {{ git = \"https://github.com/arkworks-rs/algebra/\", rev = \"2a80c54\" }}\n",
            "ark-test-curves = {{ git = \"https://github.com/arkworks-rs/algebra/\", rev = \"2a80c54\" }}\n",
            "ark-poly-commit = {{ git = \"https://github.com/arkworks-rs/poly-commit/\", rev = \"12f5529\" }}\n",
            "ark-bn254 = {{ git = \"https://github.com/arkworks-rs/curves/\", rev = \"8c0256a\" }}\n",
            "ark-pallas = {{ git = \"https://github.com/arkworks-rs/curves/\", rev = \"8c0256a\" }}\n",
            "ark-vesta = {{ git = \"https://github.com/arkworks-rs/curves/\", rev = \"8c0256a\" }}\n",
            "ark-bls12-381 = {{ git = \"https://github.com/arkworks-rs/curves/\", rev = \"3fded1f\" }}"
        )
    )?;

    // src/main.rs
    fs::write(
        host_path.join("src/main.rs"),
        HOST_TEMPLATE_SRC_MAIN
            .replace(
                "const PACKAGE: &str = \"example\"",
                "const PACKAGE: &str = \"guest\"",
            )
            .replace(
                "const EXAMPLE: &str = \"example\"",
                "const EXAMPLE: &str = \"guest\"",
            ),
    )?;

    cargo(None, ["new", guest_str])?;
    cargo(
        Some(&guest_path),
        [
            "add",
            "--git",
            "https://github.com/nexus-xyz/nexus-zkvm.git",
             "--tag",
            "0.2.1",
            "nexus-rt",
        ],
    )?;

    // add postcard because it is used for (de)serializing from/to the input/output tapes
    cargo(Some(&guest_path), ["add", "postcard", "-F", "alloc"])?;

    let mut fp2 = fs::OpenOptions::new()
        .append(true)
        .open(guest_path.join("Cargo.toml"))?;

    writeln!(
        fp2,
        concat!(
            "\n",
            "# Generated by cargo-nexus, do not remove!\n",
            "#\n",
            "# This profile is used for generating proofs, as Nexus VM support for compiler optimizations is still under development.\n",
        )
    )?;

    // guest/.cargo/config.toml
    let guest_config_path = guest_path.join(".cargo");
    fs::create_dir_all(&guest_config_path)?;
    fs::write(
        guest_config_path.join("config.toml"),
        GUEST_TEMPLATE_CARGO_CONFIG,
    )?;

    // guest/src/main.rs
    fs::write(guest_path.join("src/main.rs"), GUEST_TEMPLATE_SRC_MAIN)?;
    fs::write(guest_path.join("rust-toolchain.toml"), GUEST_RUST_TOOLCHAIN)?;

    Ok(())
}

macro_rules! host_examples_dir {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/examples")
    };
}

macro_rules! guest_examples_dir {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../examples")
    };
}

const HOST_TEMPLATE_SRC_MAIN: &str = include_str!(concat!(host_examples_dir!(), "/nova_build.rs"));

const GUEST_TEMPLATE_CARGO_CONFIG: &str = r#"[target.riscv32i-unknown-none-elf]
rustflags = [
  "-C", "link-arg=-Tlink.x",
]
runner="nexus-run"
"#;
const GUEST_TEMPLATE_SRC_MAIN: &str = include_str!(concat!(guest_examples_dir!(), "/src/main.rs"));

// freeze toolchain that works with all provers
const GUEST_RUST_TOOLCHAIN: &str = r#"[toolchain]
channel = "1.77.0"
targets = ["riscv32i-unknown-none-elf"]
"#;
