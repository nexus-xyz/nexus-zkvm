use thiserror::Error;

/// Errors that occur during dynamic compilation of guest programs.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The compile options are invalid for the memory limit.
    #[error("invalid memory configuration for selected prover")]
    InvalidMemoryConfiguration,

    /// An error occurred reading or writing to the file system.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// The compilation process failed.
    #[error("unable to compile using rustc")]
    CompilerError,
}

/// Errors that occur while reading from or writing to the input/output tapes of the zkVM.
#[derive(Debug, Error)]
pub enum TapeError {
    /// Error serializing to or deserializing from the zkVM input/output tapes.
    #[error("serialization error: {0}")]
    SerializationError(#[from] postcard::Error),

    /// Error parsing logging tape.
    #[error("encoding error: {0}")]
    EncodingError(#[from] std::string::FromUtf8Error),
}

/// Errors that occur when processing file paths.
#[derive(Debug, Error)]
pub enum PathError {
    /// Invalid encoding used for path.
    #[error("provided path has invalid encoding for use with filesystem")]
    EncodingError,
}
