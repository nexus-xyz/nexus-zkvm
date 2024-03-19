use ark_relations::r1cs::SynthesisError;
use ark_spartan::errors::ProofVerifyError;
use ark_std::{error::Error, fmt::Display};

use super::conversion::ConversionError;
pub use crate::folding::nova::cyclefold::Error as NovaError;

#[derive(Debug)]
pub enum ProofError {
    InvalidProof,
    InvalidPublicInput,
    InvalidSpartanProof(ProofVerifyError),
    SecondaryCircuitNotSatisfied,
}

#[derive(Debug)]
pub enum SpartanError {
    ConversionError(ConversionError),
    FoldingError(NovaError),
    InvalidProof(ProofError),
}

#[derive(Debug)]
pub enum SetupError {
    SynthesisError(SynthesisError),
}

impl From<SynthesisError> for SetupError {
    fn from(error: SynthesisError) -> Self {
        Self::SynthesisError(error)
    }
}

impl From<ConversionError> for SpartanError {
    fn from(error: ConversionError) -> Self {
        Self::ConversionError(error)
    }
}

impl From<NovaError> for SpartanError {
    fn from(error: NovaError) -> Self {
        Self::FoldingError(error)
    }
}

impl From<ProofError> for SpartanError {
    fn from(error: ProofError) -> Self {
        Self::InvalidProof(error)
    }
}

impl From<ProofVerifyError> for SpartanError {
    fn from(error: ProofVerifyError) -> Self {
        Self::InvalidProof(ProofError::InvalidSpartanProof(error))
    }
}

impl Error for SpartanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpartanError::ConversionError(e) => Some(e),
            SpartanError::FoldingError(e) => Some(e),
            SpartanError::InvalidProof(e) => Some(e),
        }
    }
}

impl Display for SpartanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpartanError::ConversionError(e) => write!(f, "{}", e),
            SpartanError::FoldingError(e) => write!(f, "{}", e),
            SpartanError::InvalidProof(e) => write!(f, "{}", e),
        }
    }
}

impl Error for ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProof => None,
            Self::InvalidPublicInput => None,
            Self::InvalidSpartanProof(e) => Some(e),
            Self::SecondaryCircuitNotSatisfied => None,
        }
    }
}

impl Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "Invalid proof"),
            Self::InvalidPublicInput => write!(f, "Invalid public input"),
            Self::InvalidSpartanProof(e) => write!(f, "{}", e),
            Self::SecondaryCircuitNotSatisfied => write!(f, "Secondary circuit not satisfied"),
        }
    }
}
