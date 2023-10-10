//! Concrete types and traits used by zkVM

#![cfg_attr(rustfmt, rustfmt_skip)]

pub use std::marker::PhantomData;

pub use ark_serialize::{
    CanonicalSerialize,
    CanonicalDeserialize,
};

pub use ark_ff::{
    Field,
    PrimeField
};

// concrete fields used
pub use ark_pallas::{
    Fr as F1,
    PallasConfig as G1,
    Projective as P1,
    Affine as A1,
};
pub use ark_vesta::{
    Fr as F2,
    VestaConfig as G2,
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

// circuit building macros, traits and types
pub use ark_relations::{
    lc,
    r1cs::{
        Variable,
        SynthesisMode,
        SynthesisError,
        ConstraintSystemRef
    }
};
pub use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{
        fp::{FpVar, AllocatedFp},
        FieldVar
    },
};

// types and traits from nexus prover
pub use supernova::{
    r1cs::R1CSShape,
    commitment::CommitmentScheme,
    pedersen::PedersenCommitment,
    StepCircuit,
    nova::public_params::{PublicParams, SetupParams},
    nova::sequential::PublicParams as SeqPublicParams,
    nova::sequential::IVCProof,
    nova::pcd::PublicParams as ParPublicParams,
    nova::pcd::PCDNode,
};

// concrete constraint system
pub type CS = ConstraintSystemRef<F1>;

#[cfg(feature = "ns")]
mod t {
    use super::*;
    use crate::null_schemes::*;

    // random oracle
    pub type ROConfig = ();
    pub type RO = NullRO;
    pub fn ro_config() {}

    // commitment scheme
    pub type C1 = NullCommit<P1>;
    pub type C2 = NullCommit<P2>;
}

#[cfg(not(feature = "ns"))]
mod t {
    use super::*;

    // random oracle
    pub type ROConfig = PoseidonConfig<F1>;
    pub type RO = PoseidonSponge<F1>;
    pub use supernova::poseidon_config as ro_config;

    // commitment scheme
    pub type C1 = PedersenCommitment<P1>;
    pub type C2 = PedersenCommitment<P2>;
}

pub use t::*;

// concrete public parameters
pub type PP<SP,SC> = PublicParams<G1,G2,C1,C2,RO,SC,SP>;

pub type SeqPP<SC> = SeqPublicParams<G1,G2,C1,C2,RO,SC>;
pub type ParPP<SC> = ParPublicParams<G1,G2,C1,C2,RO,SC>;
