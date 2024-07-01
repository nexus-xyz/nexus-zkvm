use std::path::Path;

pub trait ExecutionState {}

pub enum Uninitialized {}
impl ExecutionState for Uninitialized {}

pub enum Initialized {}
impl ExecutionState for Initialized {}

pub enum Traced {}
impl ExecutionState for Traced {}

pub trait Compute {}

pub enum Local {}
impl Compute for Local {}

//enum Cloud {}
//impl Cloud for Compute {}

pub trait Prover<S: ExecutionState = Uninitialized, C: Compute = Local> {
    type Memory;
    type Params;
    type Proof;
    type Error;
    
    fn gen_pp() -> Result<Self::Params, Self::Error>;

    fn load_pp(path: AsRef<Path>) -> Result<Self::Params, Self::Error>;
    
    fn save_pp(pp: &Self::Params, path: AsRef<Path>) -> Result<(), Self::Error>;

    fn new(elf_bytes: &[u8]) -> Self;

    fn new_from_file(path: AsRef<Path>) -> Self;

    fn trace<T>(self, input: Option<T>) -> Self;

    fn prove<T>(self, pp: &Self::Params, input: Option<T>) -> Result<Self::Proof, Self::Error>;
}

pub trait Verifiable {
    type Params;
    type Error;

    fn verify(&self) -> Result<(), Self::Error>;
}
