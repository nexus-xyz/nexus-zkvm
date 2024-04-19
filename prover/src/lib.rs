pub mod circuit;
pub mod error;
pub mod key;
pub mod pp;
pub mod srs;

pub mod types;

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use nexus_riscv::{VMOpts};
use nexus_vm::{memory::trie::MerkleTrie};

use nexus_nova::nova::pcd::compression::SNARK;

use crate::{
    circuit::Tr,
    error::ProofError,
    types::{ComPCDNode, ComPP, ComProof, IVCProof, PCDNode, ParPP, SeqPP, SpartanKey},
};

#[cfg(feature = "verbose")]
const TERMINAL_MODE: nexus_tui::Mode = nexus_tui::Mode::Enabled;
#[cfg(not(feature = "verbose"))]
const TERMINAL_MODE: nexus_tui::Mode = nexus_tui::Mode::Disabled;

pub const LOG_TARGET: &str = "nexus-prover";

pub fn save_proof<P: CanonicalSerialize>(proof: P, path: &Path) -> anyhow::Result<()> {
    tracing::info!(
        target: LOG_TARGET,
        path = %path.display(),
        "Saving the proof",
    );

    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let mut context = term.context("Saving").on_step(|_step| "proof".into());
    let _guard = context.display_step();

    let mut buf = Vec::new();

    proof.serialize_compressed(&mut buf)?;
    std::fs::write(path, buf)?;

    Ok(())
}

pub fn load_proof<P: CanonicalDeserialize>(path: &Path) -> Result<P, ProofError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    tracing::info!(
        target: LOG_TARGET,
        path = %path.display(),
        "Loading the proof",
    );

    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let mut context = term.context("Loading").on_step(|_step| "proof".into());
    let _guard = context.display_step();

    let proof: P = P::deserialize_compressed(reader)?;

    Ok(proof)
}

type Trace = nexus_vm::trace::Trace<nexus_vm::memory::path::Path>;

pub fn run(opts: &VMOpts, pow: bool) -> Result<Trace, ProofError> {
    Ok(nexus_riscv::nvm::run_as_nvm::<MerkleTrie>(opts, pow)?)
}

pub fn prove_seq(pp: &SeqPP, trace: Trace) -> Result<IVCProof, ProofError> {
    // let k = trace.k;
    let tr = Tr(trace);
    let icount = tr.instructions();
    let z_0 = tr.input(0)?;
    let mut proof = IVCProof::new(&z_0);

    let num_steps = tr.steps();

    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let mut term_ctx = term
        .context("Computing")
        .on_step(|step| format!("step {step}"))
        .num_steps(num_steps)
        .with_loading_bar("Proving")
        .completion_header("Proved")
        .completion_stats(move |elapsed| {
            format!(
                "{num_steps} step(s) in {elapsed}; {:.2} instructions / second",
                icount as f32 / elapsed.as_secs_f32()
            )
        });

    for _ in 0..num_steps {
        let _guard = term_ctx.display_step();

        proof = IVCProof::prove_step(proof, pp, &tr)?;
    }

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
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let mut term_ctx = term
        .context("Compressing")
        .on_step(|_step| "the proof".into());
    let _guard = term_ctx.display_step();

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
    let mut term_ctx = term
        .context("Verifying")
        .on_step(|_step| "compressed proof".into());
    let _guard = term_ctx.display_step();

    SNARK::verify(key, params, proof)?;
    Ok(())
}
