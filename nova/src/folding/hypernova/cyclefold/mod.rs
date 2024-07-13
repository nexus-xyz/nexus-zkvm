pub(crate) mod nimfs;
pub(crate) use super::super::cyclefold::secondary;

use crate::ccs;
use ark_ec::short_weierstrass::Projective;
use ark_std::fmt::Display;

pub use super::nimfs::Error as HNFoldingError;
use crate::ccs::Error as CCSError;
use crate::r1cs::Error as R1CSError;

pub(crate) type HNProof<G, RO> = super::nimfs::NIMFSProof<Projective<G>, RO>;

pub(crate) type CCSShape<G> = ccs::CCSShape<Projective<G>>;
pub(crate) type CCSInstance<G, C> = ccs::CCSInstance<Projective<G>, C>;
pub(crate) type CCSWitness<G> = ccs::CCSWitness<Projective<G>>;
pub(crate) type LCCSInstance<G, C> = ccs::LCCSInstance<Projective<G>, C>;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    R1CS(R1CSError),
    CCS(CCSError),
    HNFolding(HNFoldingError),
    Synthesis(ark_relations::r1cs::SynthesisError),

    InvalidPublicInput,
    PolyCommitmentSetup,
}

impl From<R1CSError> for Error {
    fn from(error: R1CSError) -> Self {
        Self::R1CS(error)
    }
}

impl From<CCSError> for Error {
    fn from(error: CCSError) -> Self {
        Self::CCS(error)
    }
}

impl From<HNFoldingError> for Error {
    fn from(error: HNFoldingError) -> Self {
        Self::HNFolding(error)
    }
}

impl From<ark_relations::r1cs::SynthesisError> for Error {
    fn from(error: ark_relations::r1cs::SynthesisError) -> Self {
        Self::Synthesis(error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::R1CS(error) => write!(f, "{}", error),
            Self::CCS(error) => write!(f, "{}", error),
            Self::HNFolding(error) => write!(f, "{}", error),
            Self::Synthesis(error) => write!(f, "{}", error),
            Self::InvalidPublicInput => write!(f, "invalid public input"),
            Self::PolyCommitmentSetup => write!(f, "error during polycommitment setup"),
        }
    }
}

impl ark_std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::R1CS(error) => error.source(),
            Self::CCS(error) => error.source(),
            Self::HNFolding(error) => error.source(),
            Self::Synthesis(error) => error.source(),
            Self::InvalidPublicInput => None,
            Self::PolyCommitmentSetup => None,
        }
    }
}
