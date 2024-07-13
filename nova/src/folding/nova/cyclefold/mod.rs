pub(crate) mod nimfs;
pub(crate) use super::super::cyclefold::secondary;

use ark_std::fmt::Display;

use crate::r1cs::Error as R1CSError;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    R1CS(R1CSError),
    Synthesis(ark_relations::r1cs::SynthesisError),

    InvalidPublicInput,
}

impl From<R1CSError> for Error {
    fn from(error: R1CSError) -> Self {
        Self::R1CS(error)
    }
}

impl From<ark_relations::r1cs::SynthesisError> for Error {
    fn from(error: ark_relations::r1cs::SynthesisError) -> Self {
        Self::Synthesis(error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::R1CS(error) => write!(f, "{}", error),
            Self::Synthesis(error) => write!(f, "{}", error),
            Self::InvalidPublicInput => write!(f, "invalid public input"),
        }
    }
}

impl ark_std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::R1CS(error) => error.source(),
            Self::Synthesis(error) => error.source(),
            Self::InvalidPublicInput => None,
        }
    }
}
