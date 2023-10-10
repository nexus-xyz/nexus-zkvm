use crate::types::*;

use ark_ff::AdditiveGroup;
use ark_ec::CurveGroup;
use ark_r1cs_std::{boolean::Boolean, uint8::UInt8};
use ark_crypto_primitives::{
    sponge::{
        CryptographicSponge, Absorb,
        constraints::{SpongeWithGadget, CryptographicSpongeVar, AbsorbGadget},
    },
};

pub struct NullCommit<T>(PhantomData<T>);

impl<G: CurveGroup> CommitmentScheme<G> for NullCommit<G> {
    type PP = Vec<G::MulBase>;
    type Commitment = G;

    fn setup(_n: usize) -> Self::PP {
        Vec::new()
    }

    fn commit(_pp: &Self::PP, _x: &[G::ScalarField]) -> G {
        G::ZERO
    }

    fn open(_pp: &Self::PP, _c: G, _x: &[G::ScalarField]) -> bool {
        true
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct NullRO;

impl CryptographicSponge for NullRO {
    type Config = ();

    fn new(_cfg: &Self::Config) -> Self {
        NullRO
    }

    fn absorb(&mut self, _input: &impl Absorb) {}

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        vec![0; num_bytes]
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        vec![false; num_bits]
    }
}

#[derive(Clone)]
pub struct NullROVar {
    pub var: FpVar<F1>,
    pub cs: ConstraintSystemRef<F1>,
}

impl SpongeWithGadget<F1> for NullRO {
    type Var = NullROVar;
}

impl CryptographicSpongeVar<F1, NullRO> for NullROVar {
    type Parameters = ();

    fn new(cs: ConstraintSystemRef<F1>, _params: &Self::Parameters) -> Self {
        let var = AllocatedFp::new_witness(cs.clone(), || Ok(F1::ZERO)).unwrap();
        NullROVar { var: FpVar::Var(var), cs }
    }

    fn cs(&self) -> ConstraintSystemRef<F1> {
        self.cs.clone()
    }

    fn absorb(&mut self, _input: &impl AbsorbGadget<F1>) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<F1>>, SynthesisError> {
        let zero = UInt8::constant(0);
        Ok(vec![zero; num_bytes])
    }
    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F1>>, SynthesisError> {
        let zero = Boolean::constant(false);
        Ok(vec![zero; num_bits])
    }

    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let zero = &self.var;
        Ok(vec![zero.clone(); num_elements])
    }
}
