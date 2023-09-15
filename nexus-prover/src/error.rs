use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

pub use nexus_riscv::VMError;
pub use ark_serialize::SerializationError;
use crate::types::SynthesisError;

/// Errors related to proof generation
#[derive(Debug)]
pub enum ProofError {
    /// An error occured executing program
    VMError(VMError),

    /// An error occurred reading file system
    IOError(std::io::Error),

    /// An error occured during circuit synthesis
    CircuitError(SynthesisError),

    /// An error occured serializing to disk
    SerError(SerializationError),
}
use ProofError::*;

impl From<VMError> for ProofError {
    fn from(x: VMError) -> ProofError {
        VMError(x)
    }
}

impl From<std::io::Error> for ProofError {
    fn from(x: std::io::Error) -> ProofError {
        IOError(x)
    }
}

impl From<SynthesisError> for ProofError {
    fn from(x: SynthesisError) -> ProofError {
        CircuitError(x)
    }
}

impl From<SerializationError> for ProofError {
    fn from(x: SerializationError) -> ProofError {
        SerError(x)
    }
}

impl Error for ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VMError(e) => Some(e),
            IOError(e) => Some(e),
            CircuitError(e) => Some(e),
            SerError(e) => Some(e),
        }
    }
}

impl Display for ProofError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VMError(e) => write!(f, "{e}"),
            IOError(e) => write!(f, "{e}"),
            CircuitError(e) => write!(f, "{e}"),
            SerError(e) => write!(f, "{e}"),
        }
    }
}
