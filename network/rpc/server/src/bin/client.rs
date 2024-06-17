//! Example of using jsonrpsee client.
//!
//! Create a nexus project, build it and get path to elf file, for example
//! ```sh
//! realpath target/riscv32i-unknown-none-elf/debug/my_program
//! ```
//!
//! Run the client with `cargo run -r --bin client -- <PATH TO ELF>`

use std::env;
use std::time::Duration;

use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use nexus_prover::types::IVCProof;
use nexus_rpc_common::{ArkWrapper, ElfBytes};
use nexus_rpc_traits::RpcClient;

use tracing::Level;
use tracing_subscriber::{
    filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

// type used by the RPC.
type RpcProof = ArkWrapper<IVCProof>;

#[tokio::main]
async fn main() {
    setup_logger();

    // path to elf
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("invalid number of arguments")
    }
    let path = &args[1];

    let elf_bytes = std::fs::read(path).expect("failed to read elf file");
    let proof = request(elf_bytes).await;

    let pp = nexus_rpc_server::load_params();
    proof
        .verify(&pp, proof.step_num() as usize)
        .expect("proof is invalid");

    tracing::info!(
        target: "nexus-rpc-test-client",
        "Proof is valid!"
    );
}

async fn request(elf_bytes: ElfBytes) -> RpcProof {
    let client = WsClientBuilder::default()
        .request_timeout(Duration::from_secs(180))
        .max_response_size(u32::MAX)
        .build("ws://localhost:8080")
        .await
        .unwrap();

    // client.prove() syntax is not available because of generic parameter.
    let hash = <WsClient as RpcClient<RpcProof>>::prove(&client, elf_bytes)
        .await
        .expect("prove request failed");
    <WsClient as RpcClient<RpcProof>>::get_proof(&client, hash)
        .await
        .expect("get_proof request failed")
}

fn setup_logger() {
    let filter = filter::Targets::new()
        .with_target("jsonrpsee", Level::TRACE)
        .with_target("nexus", Level::DEBUG)
        .with_default(Level::WARN);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
                .compact(),
        )
        .with(filter)
        .init()
}
