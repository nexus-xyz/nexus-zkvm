use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    /// The compile options are invalid for the memory limit
    InvalidMemoryConfiguration,

    /// An error occured reading or writing to the file system
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// The compilation process failed
    CompilerError,
}

impl Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMemoryConfiguration => {
                write!(f, "invalid memory configuration for selected prover")
            }
            Self::IOError(error) => write!(f, "{}", error),
            Self::CompilerError => write!(f, "unable to compile using rustc"),
        }
    }
}

#[derive(Debug, Error)]
pub enum TapeError {
    /// Error serializing to or deserializing from the VM input/output tapes
    SerializationError(#[from] postcard::Error),
}

impl Display for TapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationError(error) => write!(f, "{}", error),
        }
    }
}
