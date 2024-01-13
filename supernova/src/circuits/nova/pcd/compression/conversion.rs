use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use spartan::{
    crr1csproof::{CRR1CSInstance, CRR1CSShape, CRR1CSWitness},
    errors::R1CSError,
    polycommitments::PolyCommitmentScheme,
    Assignment, Instance,
};

use super::PolyVectorCommitment;
use crate::multifold::nimfs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness};

#[derive(Debug)]
pub enum ConversionError {
    ConversionError(R1CSError),
}

impl From<R1CSError> for ConversionError {
    fn from(error: R1CSError) -> Self {
        Self::ConversionError(error)
    }
}

impl<G> TryFrom<R1CSShape<G>> for CRR1CSShape<G::ScalarField>
where
    G: SWCurveConfig,
{
    type Error = ConversionError;
    fn try_from(shape: R1CSShape<G>) -> Result<Self, Self::Error> {
        let R1CSShape {
            num_constraints,
            num_vars,
            // This includes the leading `u` entry
            num_io,
            A,
            B,
            C,
        } = shape;
        // Spartan arranges the R1CS matrices using Z = [w, u, x], rather than [u, x, w]
        let rearrange =
            |matrix: Vec<(usize, usize, G::ScalarField)>| -> Vec<(usize, usize, G::ScalarField)> {
                matrix.clone().iter_mut().map(|(row, col, val)|
                // this is a witness entry 
                if *col >= num_io {
                    (*row, *col - num_io, *val)
                } else {
                    // this is an IO entry
                    (*row, *col + num_vars, *val)
                }).collect()
            };
        Ok(CRR1CSShape {
            inst: Instance::new(
                num_constraints,
                num_vars,
                // Spartan does not include the leading `u` entry in `num_inputs`.
                num_io - 1,
                rearrange(A).as_slice(),
                rearrange(B).as_slice(),
                rearrange(C).as_slice(),
            )?,
        })
    }
}

impl<G, PC> TryFrom<RelaxedR1CSInstance<G, PolyVectorCommitment<Projective<G>, PC>>>
    for CRR1CSInstance<Projective<G>, PC>
where
    G: SWCurveConfig,
    PC: PolyCommitmentScheme<Projective<G>>,
    PC::Commitment: Copy,
{
    type Error = ConversionError;
    fn try_from(
        instance: RelaxedR1CSInstance<G, PolyVectorCommitment<Projective<G>, PC>>,
    ) -> Result<Self, Self::Error> {
        let RelaxedR1CSInstance {
            commitment_W,
            commitment_E,
            X,
        } = instance;
        Ok(CRR1CSInstance {
            input: Assignment::new(&X[1..])?,
            u: X[0],
            comm_W: commitment_W,
            comm_E: commitment_E,
        })
    }
}

impl<G> TryFrom<RelaxedR1CSWitness<G>> for CRR1CSWitness<G::ScalarField>
where
    G: SWCurveConfig,
{
    type Error = ConversionError;
    fn try_from(witness: RelaxedR1CSWitness<G>) -> Result<Self, Self::Error> {
        let RelaxedR1CSWitness { W, E } = witness;
        Ok(CRR1CSWitness {
            W: Assignment::new(&W)?,
            E,
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{g1::Config as Bn254Config, Bn254};
    use ark_ec::short_weierstrass::Projective;
    use ark_ff::PrimeField;
    use ark_std::{test_rng, One};
    use spartan::{
        crr1csproof::{is_sat, CRR1CSKey},
        polycommitments::zeromorph::Zeromorph,
    };

    use super::*;
    use crate::{
        nova::pcd::compression::PVC,
        r1cs::{commit_T, Error},
        test_utils::setup_test_r1cs,
    };

    fn test_conversion_helper<G, PC>() -> Result<(), Error>
    where
        G: SWCurveConfig,
        G::BaseField: PrimeField,
        PC: PolyCommitmentScheme<Projective<G>>,
        PC::Commitment: Copy + Into<Projective<G>>,
    {
        let mut rng = test_rng();
        let srs = PC::setup(1, b"test_srs_cubic", &mut rng)
            .expect("SRS sampling should not produce an error");
        let (shape, U2, W2, pp) = setup_test_r1cs::<G, PVC<G, PC>>(3, None, Some(&srs));

        // we fold the instance and witness with themselves to get a
        // relaxed r1cs instance and witness with nontrivial error vector
        let U1 = RelaxedR1CSInstance::from(&U2);
        let W1 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &W2);

        let r = G::ScalarField::one();

        let (T, commitment_T) = commit_T(&shape, &pp, &U1, &W1, &U2, &W2)?;
        let folded_instance = U1.fold(&U2, &commitment_T, &G::ScalarField::one())?;

        let W: Vec<_> =
            W1.W.iter()
                .zip(&W2.W)
                .map(|(w1, w2)| *w1 + r * w2)
                .collect();
        let E: Vec<_> = T.iter().map(|t| r * t).collect();

        let witness = RelaxedR1CSWitness::<G> { W, E };

        // check that the folded instance-witness pair is still satisfying
        shape.is_relaxed_satisfied(&folded_instance, &witness, &pp)?;

        // convert to the corresponding Spartan types
        let shape = CRR1CSShape::<G::ScalarField>::try_from(shape).unwrap();
        let instance = CRR1CSInstance::<Projective<G>, PC>::try_from(folded_instance).unwrap();
        let witness = CRR1CSWitness::<G::ScalarField>::try_from(witness).unwrap();

        let key = CRR1CSKey { keys: pp };

        // check that the Spartan instance-witness pair is still satisfying
        assert!(is_sat(&shape, &instance, &witness, &key).unwrap());
        Ok(())
    }

    #[test]
    fn test_conversion() {
        test_conversion_helper::<Bn254Config, Zeromorph<Bn254>>().unwrap()
    }
}
