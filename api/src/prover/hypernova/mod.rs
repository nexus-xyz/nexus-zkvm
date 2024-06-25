pub use super::nova::circuit;
pub mod error;
pub mod types;

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use nexus_vm::VMOpts;

use crate::prover::hypernova::{
    error::ProofError,
    types::{IVCProof, PP, SC},
};

use super::nova::Trace;

pub fn save_proof<P: CanonicalSerialize>(proof: P, path: &Path) -> anyhow::Result<()> {
    super::nova::save_proof::<P>(proof, path)
}

pub fn load_proof<P: CanonicalDeserialize>(path: &Path) -> Result<P, ProofError> {
    super::nova::load_proof::<P>(path).map_err(ProofError::from)
}

pub fn run(opts: &VMOpts, pow: bool) -> Result<Trace, ProofError> {
    super::nova::run(opts, pow).map_err(ProofError::from)
}

pub fn init_circuit_trace(trace: Trace) -> Result<SC, ProofError> {
    super::nova::init_circuit_trace(trace).map_err(ProofError::from)
}

pub fn prove_seq(pp: &PP, trace: Trace) -> Result<IVCProof, ProofError> {
    let tr = init_circuit_trace(trace)?;

    let mut proof = prove_seq_step(None, pp, &tr)?;
    for _ in 1..tr.steps() {
        proof = prove_seq_step(Some(proof), pp, &tr)?;
    }

    Ok(proof)
}

pub fn prove_seq_step(proof: Option<IVCProof>, pp: &PP, tr: &SC) -> Result<IVCProof, ProofError> {
    let mut pr;

    if proof.is_none() {
        let z_0 = tr.input(0)?;
        pr = IVCProof::new(&z_0);
    } else {
        pr = proof.unwrap();
    }

    pr = IVCProof::prove_step(pr, pp, tr)?;
    Ok(pr)
}

#[cfg(test)]
mod tests {
    use super::*;

    use nexus_nova::poseidon_config;
    use crate::nvm::memory::MerkleTrie;
    use crate::prover::nova::circuit::nop_circuit;

    #[test]
    fn test_prove_seq() -> Result<(), ProofError> {
        let ro_config = poseidon_config();

        let circuit = nop_circuit::<MerkleTrie>(1)?;
        let trace = circuit.0.clone();

        let params = PP::test_setup(ro_config, &circuit)?;

        let proof = prove_seq(&params, trace)?;
        assert!(proof.verify(&params, proof.step_num() as _).is_ok());

        Ok(())
    }
}
