use crate::{r1cs, ccs};
use ark_ec::short_weierstrass::Projective;

pub(crate) mod secondary;

pub(crate) type R1CSShape<G> = r1cs::R1CSShape<Projective<G>>;
pub(crate) type R1CSInstance<G, C> = r1cs::R1CSInstance<Projective<G>, C>;
pub(crate) type R1CSWitness<G> = r1cs::R1CSWitness<Projective<G>>;
pub(crate) type RelaxedR1CSInstance<G, C> = r1cs::RelaxedR1CSInstance<Projective<G>, C>;
pub(crate) type RelaxedR1CSWitness<G> = r1cs::RelaxedR1CSWitness<Projective<G>>;

pub(crate) type CCSShape<G> = ccs::CCSShape<Projective<G>>;
pub(crate) type CCSInstance<G, C> = ccs::CCSInstance<Projective<G>, C>;
pub(crate) type CCSWitness<G> = ccs::CCSWitness<Projective<G>>;
pub(crate) type LCCSInstance<G, C> = ccs::LCCSInstance<Projective<G>, C>;
