use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

pub use nexus_riscv::VMError;
pub use ark_serialize::SerializationError;
pub use ark_relations::r1cs::SynthesisError;
pub use supernova::nova::Error as NovaError;
pub use supernova::r1cs::Error as R1CSError;

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

    /// The witness does not satisfy the constraints
    WitnessError(R1CSError),

    /// Public Parameters do not match circuit
    InvalidPP,

    /// The Nova prover produced an invalid proof
    NovaProofError,

    /// SRS for polynomial commitment scheme is missing
    MissingSRS,

    /// An error occured while sampling the test SRS
    SRSSamplingError,
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
            VMError(e) => Some(e),
            IOError(e) => Some(e),
            CircuitError(e) => Some(e),
            SerError(e) => Some(e),
            WitnessError(e) => Some(e),
            InvalidPP => None,
            NovaProofError => None,
            MissingSRS => None,
            SRSSamplingError => None,
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
            WitnessError(e) => write!(f, "{e}"),
            InvalidPP => write!(f, "invalid public parameters"),
            NovaProofError => write!(f, "invalid Nova proof"),
            MissingSRS => write!(f, "missing SRS"),
            SRSSamplingError => write!(f, "error sampling test SRS"),
        }
    }
}
