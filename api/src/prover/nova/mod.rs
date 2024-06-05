pub mod circuit;
pub mod error;
pub mod key;
pub mod pp;
pub mod srs;

pub mod types;

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use nexus_vm::{memory::{Memory, MemoryProof}, trace::Trace, VMOpts};

use nexus_nova::nova::pcd::compression::SNARK;

use crate::prover::nova::{
    circuit::Tr,
    error::ProofError,
    types::{ComPCDNode, ComPP, ComProof, IVCProof, PCDNode, ParPP, SeqPP, SpartanKey},
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

pub fn run<M: Memory>(opts: &VMOpts, pow: bool) -> Result<Trace<M::Proof>, ProofError> {
    Ok(nexus_vm::trace_vm::<M>(opts, pow, false)?)
}

pub fn prove_seq(pp: &SeqPP, trace: Trace) -> Result<IVCProof, ProofError> {
    let (mut proof, tr) = prove_seq_setup(pp, trace)?;
    let num_steps = tr.steps();

    for _ in 0..num_steps {
        proof = prove_seq_step(proof, pp, &tr)?;
    }

    Ok(proof)
}

pub fn prove_seq_setup(pp: &SeqPP, trace: Trace) -> Result<(IVCProof, Tr), ProofError> {
    let tr = Tr(trace, PhantomData);
    let icount = tr.instructions();
    let z_0 = tr.input(0)?;
    let mut proof = IVCProof::new(&z_0);

    Ok((proof, tr))
}

pub fn prove_seq_step(pp: &SeqPP, proof: &IVCProof, step_circuit: &Tr) -> Result<IVCProof, ProofError> {
    let proof = IVCProof::prove_step(proof, pp, step_circuit)?;
    Ok(proof)
}

macro_rules! prove_par_impl {
    ( $pp_type:ty, $node_type:ty, $name:ident ) => {
        pub fn $name(pp: $pp_type, trace: Trace) -> Result<$node_type, ProofError> {
            let k = trace.k;
            let tr = Tr(trace);

            let num_steps = tr.steps();
            assert!((num_steps + 1).is_power_of_two());

            let on_step = move |iter: usize| {
                let b = (num_steps + 1).ilog2();
                let a = b - 1 - (num_steps - iter).ilog2();

                let step = 2usize.pow(a + 1) * iter - (2usize.pow(a) - 1) * (2usize.pow(b + 1) - 1);
                let step_type = if iter <= num_steps / 2 {
                    "leaf"
                } else if iter == num_steps - 1 {
                    "root"
                } else {
                    "node"
                };
                format!("{step_type} {step}")
            };

            let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
            let mut term_ctx = term
                .context("Computing")
                .on_step(on_step)
                .num_steps(num_steps)
                .with_loading_bar("Proving")
                .completion_header("Proved")
                .completion_stats(move |elapsed| {
                    format!(
                        "tree root in {elapsed}; {:.2} instructions / second",
                        (k * num_steps) as f32 / elapsed.as_secs_f32()
                    )
                });

            let mut vs = (0..num_steps)
                .step_by(2)
                .map(|i| {
                    let _guard = term_ctx.display_step();

                    let v = <$node_type>::prove_leaf(&pp, &tr, i, &tr.input(i)?)?;
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
                        let _guard = term_ctx.display_step();
                        let c = <$node_type>::prove_parent(&pp, &tr, &ab[0], &ab[1])?;
                        Ok(c)
                    })
                    .collect::<Result<Vec<_>, ProofError>>()?;
            }

            Ok(vs.into_iter().next().unwrap())
        }
    };
}

prove_par_impl!(ParPP, PCDNode, prove_par);
prove_par_impl!(ComPP, ComPCDNode, prove_par_com);

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
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);

    SNARK::verify(key, params, proof)?;
    Ok(())
}
