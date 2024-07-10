use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::compile::*;

/// A compute resource.
pub trait Compute {}

/// Indicator type that local compute will be used for proving the zkVM.
pub enum Local {}
impl Compute for Local {}

/// A prover (and runner) for the zkVM.
pub trait Prover {
    type Memory;
    type Params: Parameters;
    type Error;

    /// Construct a new proving instance from raw ELF bytes.
    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Construct a new proving instance by reading an ELF file.
    fn new_from_file(path: &PathBuf) -> Result<Self, Self::Error>
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

    /// Run the zkVM on input of type `T` and return a view of the execution output by deserializing the output tape as of type `U`.
    fn run<T, U>(self, input: Option<T>) -> Result<impl Viewable, Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned;

    /// Prove the zkVM on input of type `T` and return a verifiable proof, along with a view of the execution output by deserializing the output tape as of type `U`.
    fn prove<T, U>(
        self,
        pp: &Self::Params,
        input: Option<T>,
    ) -> Result<impl Verifiable, Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned;
}

/// A parameter set used for proving and verifying.
pub trait Parameters {
    type Error;

    /// Generate testing parameters.
    ///
    /// In deployment, prover parameters often depend on an external reference, like a structured reference string (SRS). As such,
    /// individual provers may expose an interface for generating production parameters (e.g., [`HyperNova::Generate`](crate::hypernova::seq::Generate)).
    fn generate_for_testing() -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Load parameters from a file.
    fn load(path: &Path) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Save parameters to a file.
    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error>;
}

/// A view capturing the output of a zkVM execution.
pub trait Viewable {
    type Output;

    /// Get the logging output of the zkVM.
    fn logs(&self) -> &String;

    /// Get the contents of the output tape written by the zkVM execution.
    fn output(&self) -> &Self::Output;
}

/// A verifiable proof of a zkVM execution. Also contains a view capturing the output of the machine.
pub trait Verifiable {
    type Params: Parameters;
    type Error;
    type Output;

    /// Get the logging output of the zkVM.
    fn logs(&self) -> &String;

    /// Get the contents of the output tape written by the zkVM execution.
    fn output(&self) -> &Self::Output;

    /// Verify the proof of an execution.
    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error>;
}
