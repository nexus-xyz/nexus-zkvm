use crate::compile;
use crate::traits::*;

use std::fs;
use thiserror::Error;

use nexus_core::nvm::memory::MerkleTrie;
use nexus_core::prover::jolt::types::{JoltCommitments, JoltPreprocessing, JoltProof};
use nexus_core::prover::jolt::{
    parse_elf, preprocess, prove, trace, verify, Error as ProofError, VM as JoltVM,
};

use crate::error::{BuildError, TapeError};

use std::marker::PhantomData;

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

pub struct Jolt<C: Compute = Local> {
    vm: JoltVM<MerkleTrie>,
    _compute: PhantomData<C>,
}

pub struct Proof {
    proof: JoltProof,
    pre: JoltPreprocessing,
    commits: JoltCommitments,
}

impl Jolt<Local> {
    pub fn compile(opts: &compile::CompileOpts) -> Result<Self, Error> {
        let mut iopts = opts.to_owned();

        let elf_path = iopts
            .build(&compile::ForProver::Jolt)
            .map_err(BuildError::from)?;

        Ok(Jolt::<Local> {
            vm: parse_elf::<MerkleTrie>(fs::read(elf_path)?.as_slice())
                .map_err(ProofError::from)?,
            _compute: PhantomData,
        })
    }

    pub fn prove(self) -> Result<Proof, Error> {
        let pre = preprocess(&self.vm);
        let tr = trace(self.vm).map_err(ProofError::from)?;

        let (proof, commits) = prove(tr, &pre).map_err(ProofError::from)?;

        Ok(Proof { proof, pre, commits })
    }
}

impl Proof {
    pub fn verify(self) -> Result<(), Error> {
        Ok(verify(self.pre, self.proof, self.commits).map_err(ProofError::from)?)
    }
}
