use std::path::Path;

pub(crate) trait ExecutionState {}
pub(crate) trait Compute {}

pub trait Prover {
    type Memory;
    type Params;
    type Proof;
    type Error;
}

pub trait Configurable {
    type Memory;
    type Error;

    fn new(elf_bytes: &[u8]) -> Self;
    fn new_from_file(path: AsRef<Path>) -> Self;
}

pub trait Executable {
    type Memory;
    type Error;

    fn trace<T>(self, input: Option<T>) -> Self;
}

pub trait Provable {
    type Memory;
    type Params;
    type Proof;
    type Error;

    fn prove<T>(self, pp: &Self::Params, input: Option<T>) -> Result<Self::Proof, Self::Error>;
}

pub trait Verifiable {
    type Params;
    type Error;

    fn gen_pp() -> Result<Self::Params, Self::Error>;

    fn load_pp(path: AsRef<Path>) -> Result<Self::Params, Self::Error>;

    fn save_pp(pp: &Self::Params, path: AsRef<Path>) -> Result<(), Self::Error>;

    fn verify(&self) -> Result<(), Self::Error>;
}
