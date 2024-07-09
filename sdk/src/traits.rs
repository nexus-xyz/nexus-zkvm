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

    fn compile(opts: &CompileOpts) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<std::io::Error>;

    fn run<T, U>(self, input: Option<T>) -> Result<impl Viewable, Self::Error>
    where
        T: Serialize + Sized,
        U: DeserializeOwned;

    fn prove<T, U>(
        self,
        pp: &Self::Params,
        input: Option<T>,
    ) -> Result<impl Verifiable, Self::Error>
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

pub trait Viewable {
    type Output;

    fn logs(&self) -> &String;

    fn output(&self) -> &Self::Output;
}

pub trait Verifiable {
    type Params: Parameters;
    type Error;
    type Output;

    fn logs(&self) -> &String;

    fn output(&self) -> &Self::Output;

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error>;
}
