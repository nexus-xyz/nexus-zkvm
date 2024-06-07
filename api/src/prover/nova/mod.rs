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

type Trace = nexus_vm::trace::Trace<<MerkleTrie as Memory>::Proof>;

pub fn run(opts: &VMOpts, pow: bool) -> Result<Trace, ProofError> {
    Ok(nexus_vm::trace_vm::<MerkleTrie>(opts, pow, false)?)
}

pub fn init_circuit_trace(trace: Trace) -> Result<SC, ProofError> {
    let tr = Tr::<MerkleTrie>(trace);
    Ok(tr)
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
