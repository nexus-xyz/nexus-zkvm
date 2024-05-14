//! Example of using `nexus-prover` API.
//! Run with `cargo run --release --example prove`.

use nexus_config::{vm::NovaImpl, VmConfig};
use nexus_vm::VMOpts;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

const CONFIG: VmConfig = VmConfig { k: 16, nova_impl: NovaImpl::Sequential };

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env()
        .unwrap()
        .add_directive("r1cs=off".parse().unwrap());
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_env_filter(filter)
        .init();

    tracing::info!("Setting up public parameters...");
    let public_params = nexus_prover::pp::gen_vm_pp(CONFIG.k, &())?;

    // Run the program.
    let vm_opts = VMOpts {
        k: CONFIG.k,
        machine: Some(String::from("nop10")),
        ..Default::default()
    };
    let trace = nexus_prover::run(&vm_opts, matches!(CONFIG.nova_impl, NovaImpl::Parallel))?;

    tracing::info!("Proving execution trace...");
    let proof = nexus_prover::prove_seq(&public_params, trace)?;

    tracing::info!("Verifying proof...");
    proof.verify(&public_params, proof.step_num() as _)?;

    Ok(())
}
