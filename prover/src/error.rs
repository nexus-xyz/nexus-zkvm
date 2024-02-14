use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

pub use nexus_vm::error::NexusVMError;
pub use ark_serialize::SerializationError;
pub use ark_relations::r1cs::SynthesisError;
pub use nexus_nova::nova::Error as NovaError;
pub use nexus_nova::r1cs::Error as R1CSError;

/// Errors related to proof generation
#[derive(Debug)]
pub enum ProofError {
    /// An error occured executing program
    NexusVMError(NexusVMError),

    /// An error occurred reading file system
    IOError(std::io::Error),

    /// An error occured during circuit synthesis
    CircuitError(SynthesisError),

    /// An error occured serializing to disk
    SerError(SerializationError),

    /// The witness does not satisfy the constraints
    WitnessError(R1CSError),

    /// Invalid folding step index
    InvalidIndex(usize),

    /// Public Parameters do not match circuit
    InvalidPP,

    /// The Nova prover produced an invalid proof
    NovaProofError,
}
use ProofError::*;

impl From<NexusVMError> for ProofError {
    fn from(x: NexusVMError) -> ProofError {
        NexusVMError(x)
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

impl From<NovaError> for ProofError {
    fn from(x: NovaError) -> ProofError {
        match x {
            NovaError::R1CS(e) => WitnessError(e),
            NovaError::Synthesis(e) => CircuitError(e),
            NovaError::InvalidPublicInput => NovaProofError,
        }
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
            NexusVMError(e) => Some(e),
            IOError(e) => Some(e),
            CircuitError(e) => Some(e),
            SerError(e) => Some(e),
            WitnessError(e) => Some(e),
            InvalidPP => None,
            InvalidIndex(_) => None,
            NovaProofError => None,
        }
    }
}

impl Display for ProofError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NexusVMError(e) => write!(f, "{e}"),
            IOError(e) => write!(f, "{e}"),
            CircuitError(e) => write!(f, "{e}"),
            SerError(e) => write!(f, "{e}"),
            WitnessError(e) => write!(f, "{e}"),
            InvalidPP => write!(f, "invalid public parameters"),
            InvalidIndex(i) => write!(f, "invalid step index {i}"),
            NovaProofError => write!(f, "invalid Nova proof"),
        }
    }
}
