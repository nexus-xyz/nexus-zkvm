#![allow(unused)]

use ark_std::fmt::Display;

use super::nimfs::Error as HNFoldingError;
use crate::ccs::Error as CCSError;
use crate::r1cs::Error as R1CSError;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    R1CS(R1CSError),
    Ccs(CCSError),
    HNFolding(HNFoldingError),
    Synthesis(ark_relations::r1cs::SynthesisError),

    #[cfg(any(test, feature = "spartan"))]
    InvalidPublicInput,
}

impl From<R1CSError> for Error {
    fn from(error: R1CSError) -> Self {
        Self::R1CS(error)
    }
}

impl From<CCSError> for Error {
    fn from(error: CCSError) -> Self {
        Self::Ccs(error)
    }
}

impl From<HNFoldingError> for Error {
    fn from(error: HNFoldingError) -> Self {
        Self::HNFolding(error)
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
            Self::Ccs(error) => write!(f, "{}", error),
            Self::HNFolding(error) => write!(f, "{}", error),
            Self::Synthesis(error) => write!(f, "{}", error),
            #[cfg(any(test, feature = "spartan"))]
            Self::InvalidPublicInput => write!(f, "invalid public input"),
        }
    }
}

impl ark_std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::R1CS(error) => error.source(),
            Self::Ccs(error) => error.source(),
            Self::HNFolding(error) => error.source(),
            Self::Synthesis(error) => error.source(),
            #[cfg(any(test, feature = "spartan"))]
            Self::InvalidPublicInput => None,
        }
    }
}
