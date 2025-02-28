use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::Path;

use nexus_core::nvm::View;

use crate::error::IOError;
use crate::legacy::compile::*;
use crate::traits::*;

/// An unchecked view, the correctness of which is _not_ guaranteed by the proving or checked by the verification.
pub trait UncheckedView {}
impl UncheckedView for View {}

/// A prover for the zkVM.
pub trait LegacyProver<'a>: Setup<'a> {
    type Proof: LegacyVerifiable<'a>;
    type View: LegacyViewable;

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

    /// Run the zkVM on private input of type `S` and return a view of the execution output.
    fn run_with_input<S: Serialize + Sized>(
        self,
        private_input: &S,
    ) -> Result<Self::View, Self::Error>;

    /// Run the zkVM and return a verifiable proof, along with a view of the execution output.
    fn prove(self) -> Result<Self::Proof, Self::Error>
    where
        Self: Sized,
    {
        Self::prove_with_input::<()>(self, &())
    }

    /// Run the zkVM on private input of type `S` and return a verifiable proof, along with a view of the execution output.
    fn prove_with_input<S: Serialize + Sized>(
        self,
        private_input: &S,
    ) -> Result<Self::Proof, Self::Error>;
}

/// A view capturing the output of the machine.
pub trait LegacyViewable {
    /// Get the contents of the output tape written by the zkVM execution by deserializing the output tape as of type `U`.
    fn output<U: DeserializeOwned>(&self) -> Result<U, IOError>;

    /// Get the logging output of the zkVM.
    fn logs(&self) -> &Vec<String>;
}

/// A verifiable proof of a zkVM execution. Also contains a view capturing the output of the machine.
pub trait LegacyVerifiable<'a>: Setup<'a> + Serialize + DeserializeOwned {
    type View: LegacyViewable;

    /// Get the contents of the output tape written by the zkVM execution.
    fn output<U: DeserializeOwned>(&self) -> Result<U, Self::Error>;

    /// Get the logging output of the zkVM.
    fn logs(&self) -> &Vec<String>;

    /// Detach proof from setup to make it easier to pass around without needing to manage lifetimes.
    fn detach(&mut self);

    /// Verify the proof of an execution.
    fn verify(&self) -> Result<(), Self::Error>;
}
