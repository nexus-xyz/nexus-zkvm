// concrete fields used
pub use ark_bn254::{g1::Config as G1, Bn254 as E, Fr as F1, G1Affine as A1, G1Projective as P1};
pub use ark_grumpkin::{Affine as A2, Fr as F2, GrumpkinConfig as G2, Projective as P2};

// concrete sponge used
pub use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

pub use ark_relations::r1cs::ConstraintSystemRef;

pub use spartan::polycommitments::{zeromorph::Zeromorph, PolyCommitmentScheme};

// types and traits from nexus prover
pub use nexus_nova::{
    commitment::CommitmentScheme, hypernova::public_params::PublicParams,
    hypernova::sequential as seq, pedersen::PedersenCommitment, StepCircuit,
};
use nexus_vm::memory::trie::MerkleTrie;

// concrete constraint system
pub type CS = ConstraintSystemRef<F1>;

// random oracle
pub type ROConfig = PoseidonConfig<F1>;
pub type RO = PoseidonSponge<F1>;
pub use nexus_nova::poseidon_config as ro_config;

// polynomial commitment scheme
pub type C1 = Zeromorph<E>;

// commitment scheme
pub type C2 = PedersenCommitment<P2>;

pub type SC = crate::prover::nova::circuit::Tr<MerkleTrie>;

// concrete public parameters
pub type PP = seq::PublicParams<G1, G2, C1, C2, RO, SC>;

pub type IVCProof = seq::IVCProof<G1, G2, C1, C2, RO, SC>;
