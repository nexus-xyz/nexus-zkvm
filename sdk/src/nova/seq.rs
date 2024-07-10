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
use nexus_core::prover::nova::types::IVCProof;

use crate::error::{BuildError, TapeError};
use nexus_core::prover::nova::error::ProofError;

// re-exports
pub use nexus_core::prover::nova::types::SeqPP as PP;

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

pub struct View<U: DeserializeOwned> {
    output: U,
    logs: String,
}

pub struct Proof<U: DeserializeOwned> {
    proof: IVCProof,
    view: View<U>,
}

impl Prover for Nova<Local> {
    type Memory = MerkleTrie;
    type Params = PP;
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

    #[allow(refining_impl_trait)]
    fn run<T, U>(mut self, input: Option<T>) -> Result<View<U>, Self::Error>
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

        Ok(View {
            output: postcard::from_bytes::<U>(self.vm.syscalls.get_output().as_slice())
                .map_err(TapeError::from)?,
            logs: String::from_utf8(self.vm.syscalls.get_log_buffer()).map_err(TapeError::from)?,
        })
    }

    #[allow(refining_impl_trait)]
    fn prove<T, U>(mut self, pp: &Self::Params, input: Option<T>) -> Result<Proof<U>, Self::Error>
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

        Ok(Proof {
            proof: prove_seq(pp, tr).map_err(ProofError::from)?,
            view: View {
                output: postcard::from_bytes::<U>(self.vm.syscalls.get_output().as_slice())
                    .map_err(TapeError::from)?,
                logs: String::from_utf8(self.vm.syscalls.get_log_buffer())
                    .map_err(TapeError::from)?,
            },
        })
    }
}

impl Parameters for PP {
    type Error = Error;

    fn generate_for_testing() -> Result<Self, Self::Error> {
        Ok(gen_vm_pp(K, &()).map_err(ProofError::from)?)
    }

    fn load(path: &Path) -> Result<Self, Self::Error> {
        Ok(load_pp(path.to_str().unwrap()).map_err(ProofError::from)?)
    }

    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error> {
        Ok(save_pp(pp, path.to_str().unwrap()).map_err(ProofError::from)?)
    }
}

trait Generate {
    type Error;

    fn generate() -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl Generate for PP {
    type Error = Error;

    fn generate() -> Result<Self, Self::Error> {
        Ok(gen_vm_pp(K, &()).map_err(ProofError::from)?)
    }
}

impl<U: DeserializeOwned> Viewable for View<U> {
    type Output = U;

    fn logs(&self) -> &String {
        &self.logs
    }

    fn output(&self) -> &Self::Output {
        &self.output
    }
}

impl<U: DeserializeOwned> Verifiable for Proof<U> {
    type Params = PP;
    type Error = Error;
    type Output = U;

    fn logs(&self) -> &String {
        &self.view.logs()
    }

    fn output(&self) -> &Self::Output {
        &self.view.output()
    }

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error> {
        Ok(self.proof.verify(pp).map_err(ProofError::from)?)
    }
}
