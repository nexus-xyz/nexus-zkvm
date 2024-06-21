use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

pub use ark_relations::r1cs::SynthesisError;
pub use ark_serialize::SerializationError;
pub use nexus_nova::ccs::Error as CCSError;
pub use nexus_nova::hypernova::{Error as HyperNovaError, HNFoldingError};
pub use nexus_nova::r1cs::Error as R1CSError;
pub use nexus_vm::error::NexusVMError;

pub use crate::prover::nova::error::ProofError as NovaProofError;

/// Errors related to proof generation
#[derive(Debug)]
pub enum ProofError {
    /// An error occured loading or executing program
    NexusVMError(NexusVMError),

    /// An error occurred reading file system
    IOError(std::io::Error),

    /// An error occured during circuit synthesis
    CircuitError(SynthesisError),

    /// An error occured serializing to disk
    SerError(SerializationError),

    /// The witness does not satisfy the constraints as R1CS
    R1CSWitnessError(R1CSError),

    /// The witness does not satisfy the constraints as CCS
    CCSWitnessError(CCSError),

    /// Invalid folding step index
    InvalidIndex(usize),

    /// Public Parameters do not match circuit
    InvalidPP,

    /// An error occured while computing the HyperNova folding
    FoldingError(HNFoldingError),

    /// An error occured while setting up a polynomial commitment
    PolyCommitmentError,

    /// The HyperNova prover produced an invalid proof
    HyperNovaProofError,

    /// A proof has been read from a file that does not match the expected format
    InvalidProofFormat,
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

impl From<HyperNovaError> for ProofError {
    fn from(x: HyperNovaError) -> ProofError {
        match x {
            HyperNovaError::R1CS(e) => R1CSWitnessError(e),
            HyperNovaError::CCS(e) => CCSWitnessError(e),
            HyperNovaError::Synthesis(e) => CircuitError(e),
            HyperNovaError::HNFolding(e) => FoldingError(e),
            HyperNovaError::InvalidPublicInput => HyperNovaProofError,
            HyperNovaError::PolyCommitmentSetup => PolyCommitmentError,
        }
    }
}

impl From<SerializationError> for ProofError {
    fn from(x: SerializationError) -> ProofError {
        SerError(x)
    }
}

impl From<NovaProofError> for ProofError {
    fn from(x: NovaProofError) -> ProofError {
        match x {
            NovaProofError::NexusVMError(e) => NexusVMError(e),
            NovaProofError::IOError(e) => IOError(e),
            NovaProofError::CircuitError(e) => CircuitError(e),
            NovaProofError::SerError(e) => SerError(e),
            // The above error conversions allow reusing convienence functions
            // from the nova implemementation in this crate.
            //
            // The remaining errors are thrown by functions that are proof system
            // system specific, and so shouldn't be shared across the definitions,
            // even with identical names.
            _ => unimplemented!(),
        }
    }
}

impl Error for ProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NexusVMError(e) => Some(e),
            IOError(e) => Some(e),
            CircuitError(e) => Some(e),
            SerError(e) => Some(e),
            R1CSWitnessError(e) => Some(e),
            CCSWitnessError(e) => Some(e),
            InvalidIndex(_) => None,
            InvalidPP => None,
            FoldingError(e) => Some(e),
            PolyCommitmentError => None,
            HyperNovaProofError => None,
            InvalidProofFormat => None,
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
            R1CSWitnessError(e) => write!(f, "{e}"),
            CCSWitnessError(e) => write!(f, "{e}"),
            InvalidIndex(i) => write!(f, "invalid step index {i}"),
            InvalidPP => write!(f, "invalid public parameters"),
            FoldingError(e) => write!(f, "{e}"),
            PolyCommitmentError => write!(f, "invalid polynomial commitment setup"),
            HyperNovaProofError => write!(f, "invalid HyperNova proof"),
            InvalidProofFormat => write!(f, "invalid proof format"),
        }
    }
}
