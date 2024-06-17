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
