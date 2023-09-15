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
};
pub use ark_vesta::{
    Fr as F2,
    VestaConfig as G2,
    Projective as P2,
};

// concrete sponge used
pub use ark_crypto_primitives::{
    sponge::{
        poseidon::{
            find_poseidon_ark_and_mds,
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
    circuits::{
        StepCircuit,
        multifold::{
            PublicParams,
            RecursiveSNARK,
        },
    },
};

// concrete random oracle
pub type ROConfig = PoseidonConfig<F1>;
pub type RO = PoseidonSponge<F1>;

// concrete commitment scheme
pub type C1 = PedersenCommitment<P1>;
pub type C2 = PedersenCommitment<P2>;

// concrete public parameter
pub type PP<SC> = PublicParams<G1,G2,C1,C2,RO,SC>;

// concrete constraint system
pub type CS = ConstraintSystemRef<F1>;

/// On-disk format for public parameters
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PPDisk {
    pub ro_config: ROConfig,
    pub circuit1: R1CSShape<P1>,
    pub circuit2: R1CSShape<P2>,
    pub pp1: Vec<P1>,
    pub pp2: Vec<P2>,
    pub digest: F1,
}
