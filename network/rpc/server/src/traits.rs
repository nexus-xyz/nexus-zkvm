use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nexus_rpc_common::{hash::Hash, ElfBytes};

use super::Error;

pub trait ProofT: CanonicalSerialize + CanonicalDeserialize + Clone + Send + 'static {}
impl<T> ProofT for T where T: CanonicalSerialize + CanonicalDeserialize + Clone + Send + 'static {}

pub trait ProverT: Send + Sync + 'static {
    type Proof: ProofT;
    type Params: Send + Sync;

    fn prove(params: &Self::Params, elf_bytes: ElfBytes) -> Result<Self::Proof, Error>;
}

pub trait StorageT<T>: Send + 'static {
    type Config;

    fn new(config: Self::Config) -> Self;

    fn store(&mut self, key: Hash, value: &T) -> Result<(), Error>;

    fn get(&self, key: &Hash) -> Result<T, Error>;
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use std::collections::HashMap;

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
}
