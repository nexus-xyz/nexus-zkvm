use jsonrpsee::types::ErrorObjectOwned;
use nexus_api::prover::nova::error::ProofError;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("program hash is unknown")]
    UnknownHash,
    #[error(transparent)]
    Vm(#[from] nexus_api::nvm::NexusVMError),
    #[error("Nova error")]
    Nova(ProofError),

    #[error("prover response receiver canceled")]
    ProverRequestDropped(RecvError),
    #[error("storage response receiver canceled")]
    StorageRequestDropped(RecvError),
    #[error(transparent)]
    Serialize(#[from] ark_serialize::SerializationError),
    #[error(transparent)]
    RocksDB(#[from] rocksdb::Error),
    #[error("custom error: {0}")]
    Custom(String),
}

impl From<Error> for ErrorObjectOwned {
    fn from(error: Error) -> Self {
        // TODO: error codes
        // -32000 to -32099
        const ERROR_CODE: i32 = -32000;

        ErrorObjectOwned::owned(ERROR_CODE, error.to_string(), Option::<()>::None)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
