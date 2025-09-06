use crate::legacy::compile;
use crate::traits::*;

use std::fs;
use thiserror::Error;

use nexus_core_legacy::nvm::memory::MerkleTrie;
use nexus_core_legacy::prover::jolt::types::{JoltCommitments, JoltPreprocessing, JoltProof};
use nexus_core_legacy::prover::jolt::{
    parse_elf, preprocess, prove, trace, verify, Error as ProofError, VM as JoltVM,
};

use crate::error::{BuildError, ConfigurationError, IOError};
use std::marker::PhantomData;

/// Errors that occur while proving using Jolt.
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
    HostIOError(#[from] std::io::Error),

    /// An error occurred reading or writing to the zkVM input/output tapes.
    #[error(transparent)]
    GuestIOError(#[from] IOError),

    /// An error occurred configuring the prover.
    #[error(transparent)]
    ConfigurationError(#[from] ConfigurationError),
}

/// Prover for the Nexus zkVM using Jolt.
///
/// An experimental implementation, which does not implement the [`Prover`] trait due to missing functionality.
pub struct Jolt<C: Compute = Local> {
    vm: JoltVM<MerkleTrie>,
    pre: Option<JoltPreprocessing>,
    _compute: PhantomData<C>,
}

/// A Jolt proof (and auxiliary preprocessing information needed for verification).
//#[derive(Serialize, Deserialize)]
pub struct Proof {
    //#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    proof: (JoltProof, JoltCommitments),
    // todo: since the preprocessing is per-program, it makes sense to communicate
    //       it along with the proof, but that requires implementing serialization
    pre: JoltPreprocessing,
}

impl Jolt<Local> {
    /// Construct a new proving instance through dynamic compilation (see [`compile`]).
    pub fn compile(opts: &compile::CompileOpts) -> Result<Self, Error> {
        let mut iopts = opts.to_owned();

        let elf_path = iopts.build(&compile::ForProver::Jolt)?;

        Ok(Jolt::<Local> {
            vm: parse_elf::<MerkleTrie>(fs::read(elf_path)?.as_slice())?,
            pre: None,
            _compute: PhantomData,
        })
    }

    /// Prove the zkVM and return a verifiable proof.
    pub fn prove(mut self) -> Result<Proof, Error> {
        let pre = preprocess(&self.vm);
        self.pre = Some(pre.clone()); // keep a copy in the prover object

        let tr = trace(self.vm)?;

        let proof = prove(tr, &pre)?;

        Ok(Proof { proof, pre })
    }
}

impl<'a> Setup<'a> for Proof {
    type Reference = ();
    type Parameters = ();
    type Preprocessing = JoltPreprocessing;
    type Error = Error;

    fn setup_reference<'b: 'a>(
        &mut self,
        _reference: &'b Self::Reference,
    ) -> Result<(), Self::Error> {
        Err(Error::from(ConfigurationError::NotApplicableOperation))
    }

    fn setup_parameters<'b: 'a>(
        &mut self,
        _parameters: &'b Self::Parameters,
    ) -> Result<(), Self::Error> {
        Err(Error::from(ConfigurationError::NotApplicableOperation))
    }

    fn detach(&mut self) {}

    fn reference(&self) -> Result<&'a Self::Reference, Self::Error> {
        Ok(&())
    }

    fn parameters(&self) -> Result<&'a Self::Parameters, Self::Error> {
        Ok(&())
    }

    fn preprocessing(&self) -> Result<Self::Preprocessing, Self::Error> {
        Ok(self.pre.clone())
    }
}

impl Proof {
    /// Verify the proof of an execution.
    pub fn verify(self) -> Result<(), Error> {
        Ok(verify(self.pre, self.proof.0, self.proof.1)?)
    }
}
