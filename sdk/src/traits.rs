use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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

    fn new_from_file(
        path: &PathBuf
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<std::io::Error>
    {
        Self::new(&fs::read(path)?)
    }

    fn run<T>(self, input: Option<T>) -> Result<(), Self::Error>
    where
        T: Serialize + Sized;

    fn prove<T>(self, pp: &Self::Params, input: Option<T>) -> Result<Self::Proof, Self::Error>
    where
        T: Serialize + Sized;
}

pub trait Parameters {
    type Error;

    fn generate() -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn load(path: &PathBuf) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn save(pp: &Self, path: &PathBuf) -> Result<(), Self::Error>;
}

pub trait Verifiable {
    type Params: Parameters;
    type Error;

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error>;
}
