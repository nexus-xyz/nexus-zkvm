pub use super::nova::circuit;
pub mod error;
pub mod pp;
pub mod types;

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use nexus_vm::VMOpts;

use crate::prover::hypernova::{
    error::ProofError,
    types::{IVCProof, PP, SC},
};

use super::nova::{Trace, LOG_TARGET};

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

#[cfg(feature = "partial_prove")]
pub fn prove_partial_seq(
    pp: &PP,
    trace: Trace,
    start: usize,
    len: usize,
) -> Result<IVCProof, ProofError> {
    let tr = init_circuit_trace(trace)?;

    let end = start + len;
    if end >= tr.steps() {
        return Err(ProofError::InvalidIndex(tr.steps()));
    }

    let z_st = tr.input(start)?;
    let mut proof = IVCProof::new(&z_st);

    for _ in start..end {
        proof = prove_seq_step(Some(proof), pp, &tr)?;
    }

    Ok(proof)
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

    use crate::nvm::memory::MerkleTrie;
    use crate::prover::nova::circuit::nop_circuit;

    #[test]
    fn test_prove_seq() -> Result<(), ProofError> {
        let circuit = nop_circuit::<MerkleTrie>(1)?;
        let trace = circuit.0.clone();

        let params = pp::test_pp::gen_test_pp(&circuit)?;

        let proof = prove_seq(&params, trace)?;
        assert!(proof.verify(&params).is_ok());

        Ok(())
    }

    #[test]
    fn prove_verify_test_machine() -> Result<(), ProofError> {
        use nexus_vm::{machines::MACHINES, trace_vm};
        let public_params =
            pp::test_pp::gen_vm_test_pp(16).expect("error generating public parameters");
        for (name, _f_code, _f_result, _f_input) in MACHINES {
            let vm_opts = VMOpts {
                k: 16,
                machine: Some(name.to_string()),
                file: None,
            };
            let trace = trace_vm::<MerkleTrie>(&vm_opts, false, false, false).unwrap();
            let proof = prove_seq(&public_params, trace)
                .unwrap_or_else(|_| panic!("error proving {}", name));
            proof
                .verify(&public_params)
                .unwrap_or_else(|_| panic!("error verifying {}", name))
        }
        Ok(())
    }
}
