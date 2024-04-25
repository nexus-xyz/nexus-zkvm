use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_spartan::polycommitments::PolyCommitmentScheme;

pub mod sequential;

pub mod public_params;
use crate::commitment::CommitmentScheme;
pub use crate::folding::hypernova::cyclefold::{self, Error};
use crate::folding::hypernova::cyclefold::{nimfs::NIMFSProof, LCCSInstance};

pub use crate::circuits::nova::StepCircuit;

pub trait HyperNovaConstraintSynthesizer<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
    SC: StepCircuit<G1::ScalarField>,
{
    fn base(sumcheck_rounds: usize) -> (LCCSInstance<G1, C1>, NIMFSProof<G1, G2, C1, C2, RO>);

    // The direct construction from the HyperNova paper has a circular definition: the size
    // of the augmented circuit is dependent on the number of rounds of the sumcheck (`s`),
    // but the number of sumcheck rounds is also dependent (logarithmically) on the size of
    // the augmented circuit.
    //
    // Luckily, since the dependency is logarithmic we should pretty easily find a fixpoint
    // where this circularity stabilizes. In an ideal world, we would project the augmented
    // circuit size exactly. Unfortunately this may not be possible -- for example, at time
    // of writing we use poseidon as our hash function, which does not have a fixed circuit
    // size of its own. However, an upper bound will be good enough, with a small chance of
    // incorporating an unnecessary sumcheck round. A further tradeoff is that if we change
    // the augmented circuit then function may need to be updated.
    //
    // For an example of how this computation should work, imagine that the number of base
    // constraints (those neither in the step circuit or in sumcheck) is 20, each sumcheck
    // round has 10, and the step circuit has 2. Then we will need at least
    //
    //     2^4 < 22 < 2^5 --> 5
    //
    // sumcheck rounds. So that gives us an augmented circuit size of 72. But this means we
    // will need at least
    //
    //     2^6 < 72 < 2^7 --> 7
    //
    // sumcheck rounds. That gives an augmented circuit with size 92 -- which is a fixpoint
    // as 7 sumcheck rounds remains sufficient.
    fn project_augmented_circuit_size_upper_bound(
        step_circuit: &'_ SC,
    ) -> Result<(usize, usize), SynthesisError>;

    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>;
}
