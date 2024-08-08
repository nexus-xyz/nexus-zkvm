use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::Path;

use crate::compile::*;
use crate::error::*;

/// A compute resource.
pub trait Compute {}

/// Indicator type that local compute will be used for proving the zkVM.
pub enum Local {}
impl Compute for Local {}

/// A prover (and runner) for the zkVM.
pub trait Prover {
    type Memory;
    type Params: Parameters;
    type View: Viewable;
    type Proof: Verifiable;
    type Error;

    /// Construct a new proving instance from raw ELF bytes.
    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Construct a new proving instance by reading an ELF file.
    fn new_from_file<P: AsRef<Path>>(path: &P) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<std::io::Error>,
    {
        Self::new(&fs::read(path)?)
    }

    /// Construct a new proving instance through dynamic compilation (see [`compile`](crate::compile)).
    fn compile(opts: &CompileOpts) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<std::io::Error>;

    /// Run the zkVM and return a view of the execution output.
    fn run(self) -> Result<Self::View, Self::Error>
    where
        Self: Sized,
    {
        Self::run_with_input::<()>(self, &())
    }

    /// Run the zkVM on input of type `T` and return a view of the execution output.
    fn run_with_input<T: Serialize + Sized>(self, input: &T) -> Result<Self::View, Self::Error>;

    /// Run the zkVM and return a verifiable proof, along with a view of the execution output.
    fn prove(self, pp: &Self::Params) -> Result<Self::Proof, Self::Error>
    where
        Self: Sized,
    {
        Self::prove_with_input::<()>(self, pp, &())
    }

    /// Run the zkVM on input of type `T` and return a verifiable proof, along with a view of the execution output.
    fn prove_with_input<T: Serialize + Sized>(
        self,
        pp: &Self::Params,
        input: &T,
    ) -> Result<Self::Proof, Self::Error>;
}

/// A parameter set used for proving and verifying.
pub trait Parameters {
    type Error;

    /// Generate testing parameters.
    ///
    /// In deployment, prover parameters often depend on an external reference, like a structured reference string (SRS). As such,
    /// individual provers may expose an interface for generating production parameters (e.g., [`HyperNova::Generate`](crate::hypernova::seq::Generate)).
    fn generate_for_testing(k: usize) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Load parameters from a file.
    fn load(path: &Path) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Save parameters to a file.
    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error>;
}

/// A view capturing the output of the machine.
pub trait Viewable {
    /// Get the contents of the output tape written by the zkVM execution by deserializing the output tape as of type `U`.
    fn output<U: DeserializeOwned>(&self) -> Result<U, TapeError>;

    /// Get the logging output of the zkVM.
    fn logs(&self) -> &Vec<String>;
}

/// A verifiable proof of a zkVM execution. Also contains a view capturing the output of the machine.
pub trait Verifiable {
    type Params: Parameters;
    type View: Viewable;
    type Error;

    /// Get the contents of the output tape written by the zkVM execution by deserializing the output tape as of type `U`.
    fn output<U: DeserializeOwned>(&self) -> Result<U, Self::Error>;

    /// Get the logging output of the zkVM.
    fn logs(&self) -> &Vec<String>;

    /// Verify the proof of an execution.
    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error>;
}
