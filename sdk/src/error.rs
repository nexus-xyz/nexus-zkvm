use thiserror::Error;

/// Errors that occur when configuring or using a given prover.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// A configuration operation is not applicable for a given prover.
    #[error("operation does not apply for configured prover")]
    NotApplicableOperation,

    /// The prover or verifier was invoked without yet having been configured.
    #[error("operation invoked without required configuration having been done")]
    NotYetConfigured,
}

/// Errors that occur during dynamic compilation of guest programs.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The compile options are invalid for the memory limit (only relevant for [`legacy`](crate::legacy) provers).
    #[error("invalid memory configuration for selected prover")]
    InvalidMemoryConfiguration,

    /// An error occurred reading or writing to the file system.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// The compilation process failed.
    #[error("unable to compile using the configured compiler (e.g., rustc via Cargo)")]
    CompilerError,
}

/// Errors that occur while reading from or writing to the input/output segments and tapes of the zkVM.
#[derive(Debug, Error)]
pub enum IOError {
    /// Error serializing to or deserializing from the zkVM input/output segments and tapes.
    #[error("serialization error: {0}")]
    SerializationError(#[from] postcard::Error),

    /// Error accessing not yet available input/output entries from a [`CheckedView`](crate::traits::CheckedView).
    #[error("Unable to access input/output information: did you forget to execute the zkVM?")]
    NotYetAvailableError,

    /// Error parsing the logging tape due to an encoding issue.
    #[error("encoding  error: {0}")]
    EncodingError(#[from] std::string::FromUtf8Error),
}

/// Errors that occur while manipulating host system file paths.
#[derive(Debug, Error)]
pub enum PathError {
    /// Invalid encoding used for path.
    #[error("provided path has invalid encoding for use with filesystem")]
    EncodingError,
}
