use super::*;

use nexus_rpc_common::{hash::hash, ArkWrapper};
use nexus_rpc_traits::RpcClient;
use rpc::{build_server, run_server};

use assert_matches::assert_matches;
use jsonrpsee::core::ClientError;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};

pub mod utils;

use utils::{TestProver, TestStorage};

type Proof = ArkWrapper<<TestProver as ProverT>::Proof>;

async fn start_server() -> String {
    let server = build_server("127.0.0.1:0".parse().unwrap()).await;

    let local_addr = server.local_addr().unwrap();

    let storage = TestStorage::<<TestProver as ProverT>::Proof>::new_test();
    tokio::spawn(run_server::<TestProver, _>(server, storage, ()));

    format!("ws://{local_addr}")
}

#[tokio::test]
async fn prove_and_fetch() {
    let server_addr = start_server().await;

    let client = WsClientBuilder::new().build(server_addr).await.unwrap();

    let program = vec![1, 2, 3];
    let local_hash = hash(&program);

    let hash = <WsClient as RpcClient<Proof>>::prove(&client, program.clone())
        .await
        .unwrap();
    assert_eq!(local_hash, hash);

    let _proof = <WsClient as RpcClient<Proof>>::get_proof(&client, hash)
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_proof_not_stored() {
    let server_addr = start_server().await;

    let client = WsClientBuilder::new().build(server_addr).await.unwrap();

    let program = vec![];
    let local_hash = hash(&program);

    let response = <WsClient as RpcClient<Proof>>::prove(&client, program.clone()).await;

    let error = assert_matches!(
        response,
        Err(ClientError::Call(err)) => { err }
    );
    assert_eq!(error.code(), -32000);

    let response = <WsClient as RpcClient<Proof>>::get_proof(&client, local_hash).await;
    let error = assert_matches!(
        response,
        Err(ClientError::Call(err)) => { err }
    );
    assert_eq!(error.code(), -32000);
    assert_eq!(error.message(), "program hash is unknown");
}
