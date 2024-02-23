use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::Zero;

use super::{secondary, Error};
use crate::{
    absorb::CryptographicSpongeExt,
    commitment::{Commitment, CommitmentScheme},
    r1cs,
    ccs,
    utils::{cast_field_element, cast_field_element_unique},
};

pub(crate) mod relaxed;

pub use crate::folding::nova::nifs::{NIFSProof, SQUEEZE_ELEMENTS_BIT_SIZE};

pub(crate) use crate::folding::cyclefold::{R1CSShape, R1CSInstance, R1CSWitness, RelaxedR1CSInstance, RelaxedR1CSWitness};
