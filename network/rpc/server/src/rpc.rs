use std::net::SocketAddr;

use nexus_rpc_common::{ark_serde::ArkWrapper, hash::Hash, ElfBytes};
use nexus_rpc_traits::RpcServer;

use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, server::ServerBuilder};
use tokio::{
    sync::{mpsc, oneshot},
    task,
};

use super::{prover, storage, Error, ProverT, StorageT};

pub const LOG_TARGET: &str = "nexus-rpc";

struct Rpc<P: ProverT> {
    prover_tx: mpsc::Sender<prover::Request>,
    storage_tx: mpsc::Sender<storage::Request<P>>,
}

// jsonrpsee unconditionally adds [`serde::Serialize`] bound on generic parameter
#[async_trait]
impl<P: ProverT> RpcServer<ArkWrapper<P::Proof>> for Rpc<P> {
    async fn prove(&self, elf: ElfBytes) -> RpcResult<Hash> {
        let span = tracing::debug_span!(
            target: LOG_TARGET,
            "prove",
        );
        let _guard = span.enter();

        let (tx, rx) = oneshot::channel();
        let _ = self
            .prover_tx
            .send(prover::Request::Prove { elf, response_tx: tx })
            .await;
        let result = rx.await.map_err(Error::ProverRequestDropped)?;
        Ok(result?)
    }

    async fn get_proof(&self, hash: Hash) -> RpcResult<ArkWrapper<P::Proof>> {
        let span = tracing::debug_span!(
            target: LOG_TARGET,
            "get_proof",
            %hash,
        );
        let _guard = span.enter();

        let (tx, rx) = oneshot::channel();
        let _ = self
            .storage_tx
            .send(storage::Request::Get { hash, response_tx: tx })
            .await;
        let result = rx.await.map_err(Error::StorageRequestDropped)?;
        Ok((*result?).into())
    }
}

pub async fn run<P: ProverT, S: StorageT<P::Proof>>(
    bind_addr: SocketAddr,
    storage: S,
    prover_params: P::Params,
) {
    // TODO: env configuration
    let server = ServerBuilder::default()
        .ws_only()
        .max_request_body_size(u32::MAX)
        .max_response_body_size(u32::MAX)
        .build(bind_addr)
        .await
        .expect("failed to build server");
    let local_addr = server.local_addr().expect("local addr error");

    let (prover_tx, prover_rx) = mpsc::channel(32);
    let (storage_tx, storage_rx) = mpsc::channel(32);

    let mut tasks = task::JoinSet::new();
    tasks.spawn(prover::run::<P>(
        prover_params,
        prover_rx,
        storage_tx.clone(),
    ));
    tasks.spawn(storage::run(storage, storage_rx));

    let server_handle = server.start(Rpc { prover_tx, storage_tx }.into_rpc());
    tasks.spawn(server_handle.stopped());

    tracing::info!(
        target: LOG_TARGET,
        "Listening on ws://{local_addr}",
    );

    if let Some(_res) = tasks.join_next().await {
        tracing::error!(target: LOG_TARGET, "task unexpectedly finished");
    }
}
