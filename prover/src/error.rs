use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

pub use ark_relations::r1cs::SynthesisError;
pub use ark_serialize::SerializationError;
pub use nexus_nova::nova::{pcd::compression::SpartanError, Error as NovaError};
pub use nexus_nova::r1cs::Error as R1CSError;
pub use nexus_riscv::error::VMError as RVError;
pub use nexus_vm::error::NexusVMError;

/// Errors related to proof generation
#[derive(Debug)]
pub enum ProofError {
    /// A error occured loading program
    VMError(RVError),

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

    /// SRS for polynomial commitment scheme is missing
    MissingSRS,

    /// An error occured while sampling the test SRS
    SRSSamplingError,

    /// An error occured while running the Spartan compression prover
    CompressionError(SpartanError),

    /// A proof has been read from a file that does not match the expected format
    InvalidProofFormat,
}
use ProofError::*;

impl From<RVError> for ProofError {
    fn from(x: RVError) -> ProofError {
        VMError(x)
    }
}

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

impl From<SpartanError> for ProofError {
    fn from(x: SpartanError) -> ProofError {
        CompressionError(x)
    }
}

impl Error for ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VMError(e) => Some(e),
            NexusVMError(e) => Some(e),
            IOError(e) => Some(e),
            CircuitError(e) => Some(e),
            SerError(e) => Some(e),
            WitnessError(e) => Some(e),
            InvalidPP => None,
            InvalidIndex(_) => None,
            NovaProofError => None,
            MissingSRS => None,
            SRSSamplingError => None,
            CompressionError(e) => Some(e),
            InvalidProofFormat => None,
        }
    }
}

impl Display for ProofError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VMError(e) => write!(f, "{e}"),
            NexusVMError(e) => write!(f, "{e}"),
            IOError(e) => write!(f, "{e}"),
            CircuitError(e) => write!(f, "{e}"),
            SerError(e) => write!(f, "{e}"),
            WitnessError(e) => write!(f, "{e}"),
            InvalidPP => write!(f, "invalid public parameters"),
            InvalidIndex(i) => write!(f, "invalid step index {i}"),
            NovaProofError => write!(f, "invalid Nova proof"),
            MissingSRS => write!(f, "missing SRS"),
            SRSSamplingError => write!(f, "error sampling test SRS"),
            CompressionError(e) => write!(f, "{e}"),
            InvalidProofFormat => write!(f, "invalid proof format"),
        }
    }
}
