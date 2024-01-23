//! Concrete types and traits used by zkVM

#![cfg_attr(rustfmt, rustfmt_skip)]

pub use std::marker::PhantomData;

pub use ark_ff::{
    Field,
    PrimeField
};

// concrete fields used
pub use ark_bn254::{
    Bn254 as E,
    Fr as F1,
    g1::Config as G1,
    G1Projective as P1,
    G1Affine as A1,
    Bn254,
    g1::Config as Bn254Config
};

pub use ark_grumpkin::{
    Fr as F2,
    GrumpkinConfig as G2,
    Projective as P2,
    Affine as A2,
};

// concrete sponge used
pub use ark_crypto_primitives::{
    sponge::{
        poseidon::{
            PoseidonConfig,
            PoseidonSponge,
        }
    }
};

pub use ark_relations::r1cs::ConstraintSystemRef;

pub use spartan::polycommitments::{PolyCommitmentScheme, zeromorph::Zeromorph};

// types and traits from nexus prover
pub use supernova::{
    r1cs::{R1CSShape, R1CSWitness},
    commitment::CommitmentScheme,
    pedersen::PedersenCommitment,
    StepCircuit,
    nova::public_params::{PublicParams, SetupParams},
    nova::sequential as seq,
    nova::pcd,
    nova::pcd::compression::{self as com,
    PolyVectorCommitment},
};

// concrete constraint system
pub type CS = ConstraintSystemRef<F1>;

// random oracle
pub type ROConfig = PoseidonConfig<F1>;
pub type RO = PoseidonSponge<F1>;
pub use supernova::poseidon_config as ro_config;

// commitment scheme
pub type C1 = PedersenCommitment<P1>;
pub type C2 = PedersenCommitment<P2>;

// polynomial commitment scheme and corresponding vector commmitment scheme
pub type PC = Zeromorph<E>;
pub type PVC1 = PolyVectorCommitment<P1, PC>;

// structured reference string for polynomial commitment scheme
pub type SRS = <PC as PolyCommitmentScheme<P1>>::SRS;

pub type SC = crate::circuit::Tr;

// concrete public parameters
pub type PP<C, SP> = PublicParams<G1,G2,C,C2,RO,SC,SP>;

pub type SeqPP = seq::PublicParams<G1,G2,C1,C2,RO,SC>;
pub type ParPP = pcd::PublicParams<G1,G2,C1,C2,RO,SC>;
pub type ComPP = pcd::PublicParams<G1,G2,PVC1,C2,RO,SC>;

pub type IVCProof<'a> = seq::IVCProof<'a,G1,G2,C1,C2,RO,SC>;
pub type PCDNode = pcd::PCDNode<G1,G2,C1,C2,RO,SC>;