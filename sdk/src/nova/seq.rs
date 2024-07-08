use crate::compile;
use crate::traits::*;

use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use thiserror::Error;

use nexus_core::nvm::interactive::{eval, parse_elf, trace};
use nexus_core::nvm::memory::MerkleTrie;
use nexus_core::nvm::NexusVM;
use nexus_core::prover::nova::pp::{gen_vm_pp, load_pp, save_pp};
use nexus_core::prover::nova::prove_seq;

use crate::error::{BuildError, TapeError};
use nexus_core::prover::nova::error::ProofError;

// re-exports
pub use nexus_core::prover::nova::types::{IVCProof as Proof, SeqPP as PP};

use std::marker::PhantomData;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 64;

#[derive(Debug, Error)]
pub enum Error {
    /// An error occured during parameter generation, execution, proving, or proof verification for the VM
    #[error(transparent)]
    ProofError(#[from] ProofError),

    /// An error occured building the guest program dynamically
    #[error(transparent)]
    BuildError(#[from] BuildError),

    /// An error occured reading or writing to the file system
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// An error occured reading or writing to the VM input/output tapes
    #[error(transparent)]
    TapeError(#[from] TapeError),
}

pub struct Nova<C: Compute = Local> {
    vm: NexusVM<MerkleTrie>,
    _compute: PhantomData<C>,
}

impl Prover for Nova<Local> {
    type Memory = MerkleTrie;
    type Params = PP;
    type Proof = Proof;
    type Error = Error;

    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Nova::<Local> {
            vm: parse_elf::<Self::Memory>(elf_bytes).map_err(ProofError::from)?,
            _compute: PhantomData,
        })
    }

    fn compile(opts: &compile::CompileOpts) -> Result<Self, Self::Error> {
        let mut iopts = opts.to_owned();

        // if the user has not set the memory limit, default to 4mb
        if iopts.memlimit.is_none() {
            iopts.set_memlimit(4);
        }

        let elf_path = iopts
            .build(&compile::ForProver::Default)
            .map_err(BuildError::from)?;
        Self::new_from_file(&elf_path)
    }

    fn run<T, U>(mut self, input: Option<T>) -> Result<U, Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned,
    {
        if let Some(inp) = input {
            self.vm.syscalls.set_input(
                postcard::to_stdvec(&inp)
                    .map_err(TapeError::from)?
                    .as_slice(),
            )
        }

        eval(&mut self.vm, false, false).map_err(ProofError::from)?;

        let output: U = postcard::from_bytes::<U>(&self.vm.syscalls.get_output().as_slice())
            .map_err(TapeError::from)?;

        Ok(output)
    }

    fn prove<T, U>(
        mut self,
        pp: &Self::Params,
        input: Option<T>,
    ) -> Result<(Self::Proof, U), Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned,
    {
        if let Some(inp) = input {
            self.vm.syscalls.set_input(
                postcard::to_stdvec(&inp)
                    .map_err(TapeError::from)?
                    .as_slice(),
            )
        }

        let tr = trace(&mut self.vm, K, false).map_err(ProofError::from)?;
        let pr = prove_seq(pp, tr).map_err(ProofError::from)?;

        let output: U = postcard::from_bytes::<U>(&self.vm.syscalls.get_output().as_slice())
            .map_err(TapeError::from)?;

        Ok((pr, output))
    }
}

impl Parameters for PP {
    type Error = Error;

    fn generate() -> Result<Self, Self::Error> {
        Ok(gen_vm_pp(K, &()).map_err(ProofError::from)?)
    }

    fn load(path: &Path) -> Result<Self, Self::Error> {
        Ok(load_pp(path.to_str().unwrap()).map_err(ProofError::from)?)
    }

    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error> {
        Ok(save_pp(pp, path.to_str().unwrap()).map_err(ProofError::from)?)
    }
}

impl Verifiable for Proof {
    type Params = PP;
    type Error = Error;

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error> {
        Ok(self.verify(pp).map_err(ProofError::from)?)
    }
}
