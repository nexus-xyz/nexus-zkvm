use std::{marker::PhantomData, path::PathBuf};

use nexus_rpc_common::hash::Hash;

use tokio::sync::{mpsc, oneshot};

use super::{traits::ProofT, Error, ProverT, Result, StorageT};

const LOG_TARGET: &str = "nexus-rpc::storage";

pub struct RocksDb<T> {
    db: rocksdb::DB,
    _phantom_data: PhantomData<T>,
}

impl<T: ProofT> StorageT<T> for RocksDb<T> {
    type Config = PathBuf;

    fn new(config: Self::Config) -> Self {
        let db = rocksdb::DB::open_default(config).expect("failed to open db");
        Self { db, _phantom_data: PhantomData }
    }

    fn store(&mut self, key: Hash, value: &T) -> Result<()> {
        let mut bytes = vec![];
        value.serialize_compressed(&mut bytes)?;

        Ok(self.db.put(key, bytes)?)
    }

    fn get(&self, key: &Hash) -> std::result::Result<T, crate::Error> {
        let bytes: Vec<u8> = self.db.get(key)?.ok_or(Error::UnknownHash)?;
        Ok(T::deserialize_compressed(bytes.as_slice())?)
    }
}

#[derive(Debug)]
pub enum Request<P: ProverT> {
    Store {
        hash: Hash,
        proof: Box<P::Proof>,
        response_tx: oneshot::Sender<Result<Hash>>,
    },
    Get {
        hash: Hash,
        response_tx: oneshot::Sender<Result<Box<P::Proof>>>,
    },
}

pub async fn run<P: ProverT, S: StorageT<P::Proof>>(
    mut storage: S,
    mut req_receiver: mpsc::Receiver<Request<P>>,
) {
    while let Some(req) = req_receiver.recv().await {
        match req {
            Request::Store { hash, proof, response_tx } => {
                let result = storage.store(hash, &proof).map(|_| hash);
                if let Err(err) = &result {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %hash,
                        ?err,
                        "failed to store proof",
                    );
                }

                let _ = response_tx.send(result);
            }
            Request::Get { hash, response_tx } => {
                let result = storage.get(&hash).map(Box::new);
                if let Err(err) = &result {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %hash,
                        ?err,
                        "proof not found in storage",
                    );
                }

                let _ = response_tx.send(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        traits::test_utils::{TestProver, TestStorage},
        Error,
    };

    use ark_std::UniformRand;

    #[tokio::test]
    async fn store_proofs() {
        let storage = TestStorage::new_test();
        let (storage_tx, storage_rx) = mpsc::channel(32);

        let mut rng = ark_std::test_rng();
        let mut receivers = vec![];
        for _ in 0..10 {
            let hash = Hash::rand(&mut rng);
            let (tx, rx) = oneshot::channel();

            storage_tx
                .send(Request::Get { hash, response_tx: tx })
                .await
                .unwrap();
            receivers.push(rx);
        }

        tokio::spawn(run::<TestProver, _>(storage, storage_rx));

        for rx in receivers {
            let response = rx.await.unwrap();
            assert!(matches!(response, Err(Error::UnknownHash)));
        }

        let mut receivers = vec![];
        let mut hashes = vec![];
        for i in 0..10 {
            let hash = Hash::rand(&mut rng);
            let (tx, rx) = oneshot::channel();

            storage_tx
                .send(Request::Store {
                    hash,
                    proof: Box::new(i),
                    response_tx: tx,
                })
                .await
                .unwrap();
            rx.await.unwrap().unwrap();

            let (tx, rx) = oneshot::channel();

            storage_tx
                .send(Request::Get { hash, response_tx: tx })
                .await
                .unwrap();
            receivers.push(rx);
            hashes.push(hash);
        }

        for (i, rx) in receivers.into_iter().enumerate() {
            let response = rx.await.unwrap().unwrap();
            assert_eq!(*response, i);
        }
    }
}
