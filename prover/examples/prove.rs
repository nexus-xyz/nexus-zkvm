//! Example of using `nexus-prover` API.
//!
//! Run with `cargo run --release --example prove`. Set RUST_LOG=info for compact output.

use std::io;

use anyhow::Context;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use nexus_config::{vm::NovaImpl, VmConfig};
use nexus_vm::riscv::VMOpts;

const CONFIG: VmConfig = VmConfig { k: 16, nova_impl: NovaImpl::Sequential };

// Which example program to prove.
const EXAMPLE_NAME: &str = "fact";

fn main() -> anyhow::Result<()> {
    setup_logger();

    const TARGET_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/riscv32i-unknown-none-elf/release"
    );
    let program_path = std::path::Path::new(TARGET_PATH).join(EXAMPLE_NAME);

    if !program_path.try_exists()? {
        let error_msg = format!(
            "{}{} was not found, make sure to compile the program \
            with `cd examples && cargo build --release --bin {}`",
            "target/riscv32i-unknown-none-elf/release/", EXAMPLE_NAME, EXAMPLE_NAME,
        );
        return Err(io::Error::from(io::ErrorKind::NotFound)).context(error_msg);
    }

    // Run the program.
    let vm_opts = VMOpts {
        k: CONFIG.k,
        file: Some(program_path),
        ..Default::default()
    };
    let trace = nexus_prover::run(&vm_opts, matches!(CONFIG.nova_impl, NovaImpl::Parallel))?;

    tracing::info!("Setting up public parameters...");
    let public_params = nexus_prover::pp::gen_vm_pp(CONFIG.k, &())?;

    tracing::info!("Proving execution trace...");
    let proof = nexus_prover::prove_seq(&public_params, trace)?;

    tracing::info!("Verifying proof...");
    proof.verify(&public_params, proof.step_num() as _)?;

    Ok(())
}

fn setup_logger() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env()
        .unwrap()
        .add_directive("r1cs=off".parse().unwrap());
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_env_filter(filter)
        .init();
}
