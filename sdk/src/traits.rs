use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub trait Compute {}

pub enum Local {}
impl Compute for Local {}

pub trait Prover {
    type Memory;
    type Params: Parameterized;
    type Proof: Verifiable;
    type Error;

    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn new_from_file(path: &PathBuf) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn run<T>(self, input: Option<T>) -> Result<(), Self::Error>
    where
        T: Serialize + Sized;

    fn prove<T>(self, pp: &Self::Params, input: Option<T>) -> Result<Self::Proof, Self::Error>
    where
        T: Serialize + Sized;
}

pub trait Parameterized {
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
    type Params: Parameterized;
    type Error;

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error>;
}
