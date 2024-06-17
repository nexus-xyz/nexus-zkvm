use std::collections::HashMap;

use nexus_rpc_common::{hash::Hash, ElfBytes};

use crate::{Error, ProverT, StorageT};

/// Test prover that returns non-zero length of elf bytes as a proof,
/// and an error otherwise.
#[derive(Debug)]
pub struct TestProver;

impl ProverT for TestProver {
    type Proof = usize;
    type Params = ();

    fn prove(_: &(), elf: ElfBytes) -> Result<Self::Proof, Error> {
        if elf.is_empty() {
            Err(Error::Custom("error".into()))
        } else {
            Ok(elf.len())
        }
    }
}

/// Hashmap storage.
pub struct TestStorage<T>(HashMap<Hash, T>);

impl<T: Send + Clone + 'static> TestStorage<T> {
    pub fn new_test() -> Self {
        Self::new(())
    }
}

impl<T: Send + Clone + 'static> StorageT<T> for TestStorage<T> {
    type Config = ();

    fn new(_: Self::Config) -> Self {
        Self(HashMap::new())
    }

    fn store(&mut self, key: Hash, value: &T) -> Result<(), Error> {
        self.0.insert(key, value.clone());
        Ok(())
    }

    fn get(&self, key: &Hash) -> Result<T, Error> {
        self.0.get(key).cloned().ok_or(Error::UnknownHash)
    }
}
