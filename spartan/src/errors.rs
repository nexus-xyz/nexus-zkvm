use super::polycommitments::error::PCSError;
use ark_serialize::SerializationError;
use ark_std::{error::Error, fmt::Display};
use core::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug, Default)]
pub enum ProofVerifyError {
  #[error("Proof verification failed")]
  #[default]
  InternalError,
  #[error("Compressed group element failed to decompress: {0:?}")]
  DecompressionError([u8; 32]),
  #[error("PolyCommitment error: {0:?}")]
  PolyCommitmentError(PCSError),
}

#[derive(Debug)]
pub enum R1CSError {
  /// returned if the number of constraints is not a power of 2
  NonPowerOfTwoCons,
  /// returned if the number of variables is not a power of 2
  NonPowerOfTwoVars,
  /// returned if a wrong number of inputs in an assignment are supplied
  InvalidNumberOfInputs,
  /// returned if a wrong number of variables in an assignment are supplied
  InvalidNumberOfVars,
  /// returned if a [u8;32] does not parse into a valid Scalar in the field of ristretto255
  InvalidScalar,
  /// returned if the supplied row or col in (row,col,val) tuple is out of range
  InvalidIndex,
  /// Ark serialization error
  ArkSerializationError(SerializationError),
}

impl From<SerializationError> for R1CSError {
  fn from(e: SerializationError) -> Self {
    Self::ArkSerializationError(e)
  }
}

impl Error for R1CSError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match self {
      Self::NonPowerOfTwoCons => None,
      Self::NonPowerOfTwoVars => None,
      Self::InvalidNumberOfInputs => None,
      Self::InvalidNumberOfVars => None,
      Self::InvalidScalar => None,
      Self::InvalidIndex => None,
      Self::ArkSerializationError(e) => Some(e),
    }
  }
}

impl Display for R1CSError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::NonPowerOfTwoCons => write!(f, "Non power of two constraints"),
      Self::NonPowerOfTwoVars => write!(f, "Non power of two variables"),
      Self::InvalidNumberOfInputs => write!(f, "Invalid number of inputs"),
      Self::InvalidNumberOfVars => write!(f, "Invalid number of variables"),
      Self::InvalidScalar => write!(f, "Invalid scalar"),
      Self::InvalidIndex => write!(f, "Invalid index"),
      Self::ArkSerializationError(e) => write!(f, "{e}"),
    }
  }
}

impl From<PCSError> for ProofVerifyError {
  fn from(e: PCSError) -> Self {
    Self::PolyCommitmentError(e)
  }
}
