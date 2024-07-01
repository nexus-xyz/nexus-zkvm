mod error;
mod nova;
mod prover;
mod storage;
#[cfg(test)]
mod tests;
mod traits;

pub mod rpc;

pub(crate) use error::{Error, Result};
pub(crate) use traits::{ProverT, StorageT};

// re-export for the example client
#[doc(hidden)]
pub use nova::load_params;

type RocksDB = storage::RocksDb<<nova::NovaProver as ProverT>::Proof>;

pub async fn run(config: nexus_core::config::network::rpc::RpcConfig) {
    tracing::info!(
        target: rpc::LOG_TARGET,
        "RPC config: {config:?}",
    );

    let storage = RocksDB::new(config.db_path);
    let params = nova::load_params();
    rpc::run::<nova::NovaProver, RocksDB>(config.bind_addr, storage, params).await;
}
