pub(crate) mod nimfs;
pub(crate) mod secondary;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    R1CS(super::r1cs::Error),
    Synthesis(ark_relations::r1cs::SynthesisError),

    #[cfg(any(test, feature = "spartan"))]
    InvalidPublicInput,
}

impl From<super::r1cs::Error> for Error {
    fn from(error: super::r1cs::Error) -> Self {
        Self::R1CS(error)
    }
}

impl From<ark_relations::r1cs::SynthesisError> for Error {
    fn from(error: ark_relations::r1cs::SynthesisError) -> Self {
        Self::Synthesis(error)
    }
}
