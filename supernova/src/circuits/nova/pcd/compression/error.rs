use ark_relations::r1cs::SynthesisError;
use spartan::errors::ProofVerifyError;

use super::conversion::ConversionError;
pub use crate::multifold::Error as NovaError;

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
