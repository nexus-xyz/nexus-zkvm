use std::sync::Arc;

use nexus_rpc_common::{
    hash::{hash, Hash},
    ElfBytes,
};

use tokio::sync::{mpsc, oneshot};

use super::{storage, ProverT, Result};

const LOG_TARGET: &str = "nexus-rpc::prover";

pub enum Request {
    Prove {
        elf: ElfBytes,
        response_tx: oneshot::Sender<Result<Hash>>,
    },
}

// Payload returned from the rayon thread.
// (hash, result from rayon, sender back to rpc)
type Payload<T> = (Hash, Result<Box<T>>, oneshot::Sender<Result<Hash>>);

fn handle_prove_req<P: ProverT>(
    params: Arc<P::Params>,
    tx: mpsc::Sender<Payload<P::Proof>>,
    response_tx: oneshot::Sender<Result<Hash>>,
    elf: ElfBytes,
) {
    rayon::spawn(move || {
        let _span = tracing::debug_span!(
            target: LOG_TARGET,
            "handle_prove_req",
        )
        .entered();

        let hash = hash(&elf);
        let proof = P::prove(params.as_ref(), elf).map(Box::new);
        tx.blocking_send((hash, proof, response_tx))
            .expect("send from thread pool failed");
    });
}

pub async fn run<P: ProverT>(
    params: P::Params,
    mut req_receiver: mpsc::Receiver<Request>,
    storage_sender: mpsc::Sender<storage::Request<P>>,
) {
    let (tx, mut rx) = mpsc::channel::<Payload<P::Proof>>(32);
    let params = Arc::new(params);

    loop {
        tokio::select! {
            biased;
            Some((hash, result, response_tx)) = rx.recv() => {
                match result {
                    Ok(proof) => {
                        storage_sender
                            .send(storage::Request::Store { hash, proof, response_tx })
                            .await
                            .expect("storage receiver dropped");
                    }
                    Err(err) => {
                        // send error back
                        let _ = response_tx.send(Err(err));
                    }
                }
            }
            Some(req) = req_receiver.recv() => {
                let Request::Prove { elf, response_tx } = req;

                handle_prove_req::<P>(params.clone(), tx.clone(), response_tx, elf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{traits::test_utils::*, Error};

    #[tokio::test]
    async fn send_requests() {
        let (req_tx, req_rx) = mpsc::channel(32);
        let (storage_tx, mut storage_rx) = mpsc::channel(32);

        // stack requests into the channel to simulate load
        for i in 1..4 {
            let (tx, _) = oneshot::channel();
            req_tx
                .send(Request::Prove {
                    elf: Vec::from_iter(1..=i), // [1] [1, 2] [1, 2, 3]
                    response_tx: tx,
                })
                .await
                .unwrap();
        }

        let params = ();
        tokio::spawn(run::<TestProver>(params, req_rx, storage_tx));

        let mut proofs = vec![];
        for _ in 1..4 {
            match storage_rx.recv().await.unwrap() {
                storage::Request::Store { proof, .. } => proofs.push(proof),
                _ => panic!("unexpected message"),
            }
        }

        for len in 1..4 {
            assert!(proofs.iter().any(|p| **p == len));
        }

        // an error should be reported back bypassing the storage
        let (tx, rx) = oneshot::channel();
        req_tx
            .send(Request::Prove { elf: Vec::new(), response_tx: tx })
            .await
            .unwrap();

        assert!(matches!(rx.await.unwrap(), Err(Error::Custom(_))));
    }
}
