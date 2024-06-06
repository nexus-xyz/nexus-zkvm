//! Default types and traits for use by zkVM

pub use std::marker::PhantomData;

pub use ark_ff::{Field, PrimeField};

// concrete fields used
pub use ark_bn254::{g1::Config as G1, Bn254 as E, Fr as F1, G1Affine as A1, G1Projective as P1};
pub use ark_grumpkin::{Affine as A2, Fr as F2, GrumpkinConfig as G2, Projective as P2};

// concrete sponge used
pub use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

pub use ark_relations::r1cs::ConstraintSystemRef;

pub use spartan::polycommitments::{zeromorph::Zeromorph, PolyCommitmentScheme};

// types and traits from nexus prover
use nexus_vm::memory::trie::MerkleTrie;
pub use nexus_nova::{
    commitment::CommitmentScheme,
    nova::pcd,
    nova::pcd::compression as com,
    nova::public_params::{PublicParams, SetupParams},
    nova::sequential as seq,
    pedersen::PedersenCommitment,
    r1cs::{R1CSShape, R1CSWitness},
    StepCircuit,
};

// concrete constraint system
pub type CS = ConstraintSystemRef<F1>;

// random oracle
pub type ROConfig = PoseidonConfig<F1>;
pub type RO = PoseidonSponge<F1>;
pub use nexus_nova::poseidon_config as ro_config;

// commitment scheme
pub type C1 = PedersenCommitment<P1>;
pub type C2 = PedersenCommitment<P2>;

// polynomial commitment scheme and corresponding vector commmitment scheme
pub type PC = Zeromorph<E>;
pub type PVC1 = com::PolyVectorCommitment<P1, PC>;

// structured reference string for polynomial commitment scheme
pub type SRS = <PC as PolyCommitmentScheme<P1>>::SRS;

pub type SC = crate::prover::nova::circuit::Tr<MerkleTrie>;

// concrete public parameters
pub type PP<C, SP> = PublicParams<G1, G2, C, C2, RO, SC, SP>;

pub type SeqPP = seq::PublicParams<G1, G2, C1, C2, RO, SC>;
pub type ParPP = pcd::PublicParams<G1, G2, C1, C2, RO, SC>;
pub type ComPP = pcd::PublicParams<G1, G2, PVC1, C2, RO, SC>;

pub type SpartanKey = com::SNARKKey<P1, PC>;

pub type IVCProof = seq::IVCProof<G1, G2, C1, C2, RO, SC>;
pub type PCDNode = pcd::PCDNode<G1, G2, C1, C2, RO, SC>;
pub type ComPCDNode = pcd::PCDNode<G1, G2, PVC1, C2, RO, SC>;
pub type ComProof = com::CompressedPCDProof<G1, G2, PC, C2, RO, SC>;
