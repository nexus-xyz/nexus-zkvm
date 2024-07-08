use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::compile::*;

pub trait Compute {}

pub enum Local {}
impl Compute for Local {}

pub trait Prover {
    type Memory;
    type Params: Parameters;
    type Proof: Verifiable;
    type Error;

    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn new_from_file(path: &PathBuf) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<std::io::Error>,
    {
        Self::new(&fs::read(path)?)
    }

    fn compile(opts: &CompileOpts) -> Result<PathBuf, BuildError>
    where
        Self: Sized,
        Self::Error: From<std::io::Error>;

    fn run<T, U>(self, input: Option<T>) -> Result<U, Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned;

    fn prove<'a, T, U>(
        self,
        pp: &Self::Params,
        input: Option<T>,
    ) -> Result<(Self::Proof, U), Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned;
}

pub trait Parameters {
    type Error;

    fn generate() -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn load(path: &Path) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error>;
}

pub trait Verifiable {
    type Params: Parameters;
    type Error;

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error>;
}
