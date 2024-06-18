//! Interface declaration for both the server and the client.
//!
//! Provides [`RpcServer`] and [`RpcClient`] traits.
//! The client trait is auto-implemented for [`jsonrpsee::ws_client::WsClient`].
//!
//! Since the server response is an untagged sequence of bytes, the client should
//! be aware of which generic type should be used.
//!
//! See doc-comments for [`jsonrpsee::proc_macros::rpc`].

use nexus_rpc_common::{hash::Hash, ElfBytes};

#[cfg(feature = "server")]
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[cfg_attr(feature = "server", rpc(server, client))]
#[cfg_attr(not(feature = "server"), rpc(client))]
pub trait Rpc<T> {
    /// Request the server to run the elf file on NexusVM and prove the execution trace.
    /// This method blocks until the proof is computed.
    ///
    /// Returns the proof identifier on success.
    #[method(name = "prove")]
    async fn prove(&self, elf: ElfBytes) -> RpcResult<Hash>;

    /// Request to download the proof with provided hash-identifier.
    #[method(name = "getProof")]
    async fn get_proof(&self, hash: Hash) -> RpcResult<T>;
}
