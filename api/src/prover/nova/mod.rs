pub mod circuit;
pub mod error;
pub mod key;
pub mod pp;
pub mod srs;

pub mod types;

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use nexus_vm::{
    memory::{trie::MerkleTrie, Memory},
    VMOpts,
};

use nexus_nova::nova::pcd::compression::SNARK;

use crate::prover::nova::{
    circuit::Tr,
    error::ProofError,
    types::{ComPCDNode, ComPP, ComProof, IVCProof, PCDNode, ParPP, SeqPP, SpartanKey, SC},
};

pub const LOG_TARGET: &str = "nexus-prover";

pub fn save_proof<P: CanonicalSerialize>(proof: P, path: &Path) -> anyhow::Result<()> {
    tracing::info!(
         target: LOG_TARGET,
         path = %path.display(),
        "Saving the proof",
    );

    let mut buf = Vec::new();

    proof.serialize_compressed(&mut buf)?;
    std::fs::write(path, buf)?;

    Ok(())
}

pub fn load_proof<P: CanonicalDeserialize>(path: &Path) -> Result<P, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = %path.display(),
        "Loading the proof",
    );

    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let proof: P = P::deserialize_compressed(reader)?;

    Ok(proof)
}

pub(crate) type Trace = nexus_vm::trace::Trace<<MerkleTrie as Memory>::Proof>;

pub fn run(opts: &VMOpts, pow: bool) -> Result<Trace, ProofError> {
    Ok(nexus_vm::trace_vm::<MerkleTrie>(opts, pow, false)?)
}

pub fn init_circuit_trace(trace: Trace) -> Result<SC, ProofError> {
    let tr = Tr::<MerkleTrie>(trace);
    Ok(tr)
}

pub fn prove_seq(pp: &SeqPP, trace: Trace) -> Result<IVCProof, ProofError> {
    let tr = init_circuit_trace(trace)?;

    let mut proof = prove_seq_step(None, pp, &tr)?;
    for _ in 1..tr.steps() {
        proof = prove_seq_step(Some(proof), pp, &tr)?;
    }

    Ok(proof)
}

pub fn prove_seq_step(
    proof: Option<IVCProof>,
    pp: &SeqPP,
    tr: &SC,
) -> Result<IVCProof, ProofError> {
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

macro_rules! prove_par_impl {
    ( $pp_type:ty, $node_type:ty, $name:ident, $leaf_step_name:ident, $parent_step_name:ident) => {
        pub fn $name(pp: &$pp_type, trace: Trace) -> Result<$node_type, ProofError> {
            let tr = init_circuit_trace(trace)?;
            let num_steps = tr.steps();

            assert!((tr.steps() + 1).is_power_of_two());

            let mut vs = (0..num_steps)
                .step_by(2)
                .map(|i| {
                    // todo: replace with concat_idents once stable
                    let v = $leaf_step_name(pp, &tr, i)?;
                    Ok(v)
                })
                .collect::<Result<Vec<_>, ProofError>>()?;

            loop {
                if vs.len() == 1 {
                    break;
                }

                vs = vs
                    .chunks(2)
                    .map(|ab| {
                        // todo: replace with concat_idents once stable
                        let c = $parent_step_name(pp, &tr, &ab[0], &ab[1])?;
                        Ok(c)
                    })
                    .collect::<Result<Vec<_>, ProofError>>()?;
            }

            Ok(vs.into_iter().next().unwrap())
        }
    };
}

macro_rules! prove_par_leaf_step_impl {
    ( $pp_type:ty, $node_type:ty, $name:ident ) => {
        pub fn $name(pp: &$pp_type, tr: &SC, i: usize) -> Result<$node_type, ProofError> {
            assert!((tr.steps() + 1).is_power_of_two());

            let v = <$node_type>::prove_leaf(pp, tr, i, &tr.input(i)?)?;
            Ok(v)
        }
    };
}

macro_rules! prove_par_parent_step_impl {
    ( $pp_type:ty, $node_type:ty, $name:ident ) => {
        pub fn $name(
            pp: &$pp_type,
            tr: &SC,
            ab0: &$node_type,
            ab1: &$node_type,
        ) -> Result<$node_type, ProofError> {
            assert!((tr.steps() + 1).is_power_of_two());

            let c = <$node_type>::prove_parent(pp, tr, ab0, ab1)?;
            Ok(c)
        }
    };
}

prove_par_leaf_step_impl!(ParPP, PCDNode, prove_par_leaf_step);
prove_par_leaf_step_impl!(ComPP, ComPCDNode, prove_par_com_leaf_step);
prove_par_parent_step_impl!(ParPP, PCDNode, prove_par_parent_step);
prove_par_parent_step_impl!(ComPP, ComPCDNode, prove_par_com_parent_step);
prove_par_impl!(
    ParPP,
    PCDNode,
    prove_par,
    prove_par_leaf_step,
    prove_par_parent_step
);
prove_par_impl!(
    ComPP,
    ComPCDNode,
    prove_par_com,
    prove_par_com_leaf_step,
    prove_par_com_parent_step
);

pub fn compress(
    compression_pp: &ComPP,
    key: &SpartanKey,
    node: ComPCDNode,
) -> Result<ComProof, ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        "Compressing the proof",
    );

    let compressed_pcd_proof = SNARK::compress(compression_pp, key, node)?;

    Ok(compressed_pcd_proof)
}

pub fn verify_compressed(
    key: &SpartanKey,
    params: &ComPP,
    proof: &ComProof,
) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        "Verifying the compressed proof",
    );

    SNARK::verify(key, params, proof)?;
    Ok(())
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

        let params = SeqPP::setup(ro_config, &circuit, &(), &())?;

        let proof = prove_seq(&params, trace)?;
        assert!(proof.verify(&params, proof.step_num() as _).is_ok());

        Ok(())
    }
}
