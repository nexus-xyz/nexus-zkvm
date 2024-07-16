use crate::compile;
use crate::traits::*;
use crate::views::UncheckedView;

use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use thiserror::Error;

use nexus_core::nvm::interactive::{eval, parse_elf, trace};
use nexus_core::nvm::memory::MerkleTrie;
use nexus_core::nvm::NexusVM;
use nexus_core::prover::nova::pp::{gen_vm_pp, load_pp, save_pp};
use nexus_core::prover::nova::prove_seq;
use nexus_core::prover::nova::types::IVCProof;

use crate::error::{BuildError, PathError, TapeError};
use nexus_core::prover::nova::error::ProofError;

// re-exports
/// Public parameters used to prove and verify zkVM executions.
pub use nexus_core::prover::nova::types::SeqPP as PP;

use std::marker::PhantomData;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 64;

/// Errors that occur while proving using Nova.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occurred during parameter generation, execution, proving, or proof verification for the zkVM.
    #[error(transparent)]
    ProofError(#[from] ProofError),

    /// An error occurred building the guest program dynamically.
    #[error(transparent)]
    BuildError(#[from] BuildError),

    /// An error occurred reading or writing to the filesystem.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// An error occurred trying to parse a path for use with the filesystem.
    #[error(transparent)]
    PathError(#[from] PathError),

    /// An error occurred reading or writing to the zkVM input/output tapes.
    #[error(transparent)]
    TapeError(#[from] TapeError),
}

/// Prover for the Nexus zkVM using Nova.
pub struct Nova<C: Compute = Local> {
    vm: NexusVM<MerkleTrie>,
    _compute: PhantomData<C>,
}

/// A verifiable proof of a zkVM execution. Also contains a view capturing the output of the machine.
///
/// **Warning**: The proof contains an _unchecked_ view. Please review [`UncheckedView`].
pub struct Proof {
    proof: IVCProof,
    view: UncheckedView,
}

impl Prover for Nova<Local> {
    type Memory = MerkleTrie;
    type Params = PP;
    type View = UncheckedView;
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

    fn run_with_input<T>(mut self, input: &T) -> Result<Self::View, Self::Error>
    where
        T: Serialize + Sized,
    {
        self.vm.syscalls.set_input(
            postcard::to_stdvec(input)
                .map_err(TapeError::from)?
                .as_slice(),
        );

        eval(&mut self.vm, false, false).map_err(ProofError::from)?;

        Ok(Self::View {
            output: self.vm.syscalls.get_output(),
            logs: self
                .vm
                .syscalls
                .get_log_buffer()
                .into_iter()
                .map(String::from_utf8)
                .collect::<Result<Vec<_>, _>>()
                .map_err(TapeError::from)?,
        })
    }

    fn prove_with_input<T>(
        mut self,
        pp: &Self::Params,
        input: &T,
    ) -> Result<Self::Proof, Self::Error>
    where
        T: Serialize + Sized,
    {
        self.vm.syscalls.set_input(
            postcard::to_stdvec(input)
                .map_err(TapeError::from)?
                .as_slice(),
        );

        let tr = trace(&mut self.vm, K, false).map_err(ProofError::from)?;

        Ok(Self::Proof {
            proof: prove_seq(pp, tr).map_err(ProofError::from)?,
            view: Self::View {
                output: self.vm.syscalls.get_output(),
                logs: self
                    .vm
                    .syscalls
                    .get_log_buffer()
                    .into_iter()
                    .map(String::from_utf8)
                    .collect::<Result<Vec<_>, _>>()
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
        if let Some(path_str) = path.to_str() {
            return Ok(load_pp(path_str).map_err(ProofError::from)?);
        }

        Err(Self::Error::PathError(
            crate::error::PathError::EncodingError,
        ))
    }

    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error> {
        if let Some(path_str) = path.to_str() {
            return Ok(save_pp(pp, path_str).map_err(ProofError::from)?);
        }

        Err(Self::Error::PathError(
            crate::error::PathError::EncodingError,
        ))
    }
}

/// Generate a deployment-ready parameter set used for proving and verifying.
pub trait Generate {
    type Error;

    /// Generate parameters.
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

impl Verifiable for Proof {
    type Params = PP;
    type View = UncheckedView;
    type Error = Error;

    fn output<U: DeserializeOwned>(&self) -> Result<U, Self::Error> {
        Ok(Self::View::output::<U>(&self.view)?)
    }

    fn logs(&self) -> &Vec<String> {
        Self::View::logs(&self.view)
    }

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error> {
        Ok(self.proof.verify(pp).map_err(ProofError::from)?)
    }
}
