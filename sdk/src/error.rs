use std::fmt::Display;
use thiserror::Error;

/// Errors that occur during dynamic compilation of guest programs.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The compile options are invalid for the memory limit.
    InvalidMemoryConfiguration,

    /// An error occurred reading or writing to the file system.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// An error occurred generating the compile time configuration.
    #[error(transparent)]
    ConfigError(#[from] postcard::Error),

    /// The compilation process failed.
    CompilerError,
}

impl Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMemoryConfiguration => {
                write!(f, "invalid memory configuration for selected prover")
            }
            Self::IOError(error) => write!(f, "{}", error),
            Self::ConfigError(error) => write!(f, "{}", error),
            Self::CompilerError => write!(f, "unable to compile using rustc"),
        }
    }
}

/// Errors that occur while reading from or writing to the input/output tapes of the zkVM.
#[derive(Debug, Error)]
pub enum TapeError {
    /// Error serializing to or deserializing from the zkVM input/output tapes.
    SerializationError(#[from] postcard::Error),

    /// Error parsing logging tape.
    EncodingError(#[from] std::string::FromUtf8Error),
}

impl Display for TapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationError(error) => write!(f, "{}", error),
            Self::EncodingError(error) => write!(f, "{}", error),
        }
    }
}

#[derive(Debug, Error)]
pub enum PathError {
    /// Invalid encoding used for path.
    EncodingError,
}

impl Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncodingError => write!(
                f,
                "provided path has invalid encoding for use with filesystem"
            ),
        }
    }
}
