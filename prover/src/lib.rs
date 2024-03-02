pub mod circuit;
pub mod error;
pub mod key;
pub mod pp;
pub mod srs;

use std::time::Instant;
pub mod types;

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use nexus_vm::{
    riscv::{load_nvm, VMOpts},
    trace::{trace, Trace},
};

use nexus_nova::nova::pcd::compression::SNARK;

use crate::{
    circuit::Tr,
    error::ProofError,
    types::{ComPCDNode, ComPP, ComProof, IVCProof, PCDNode, ParPP, SeqPP, SpartanKey},
};

pub const LOG_TARGET: &str = "nexus-prover";

#[derive(Default, Clone, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct Proof {
    pub hash: String,
    pub total_nodes: u32,
    pub complete_nodes: u32,
    pub par: bool,
    pub com: bool,
    pub proof: Option<Vec<u8>>,
}

pub fn save_proof<P: CanonicalSerialize>(proof: P, path: &Path) -> anyhow::Result<()> {
    tracing::info!(
        target: LOG_TARGET,
        path = %path.display(),
        "Saving the proof",
    );

    let mut term = nexus_tui::TerminalHandle::new();
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

    let mut term = nexus_tui::TerminalHandle::new();
    let mut context = term.context("Loading").on_step(|_step| "proof".into());
    let _guard = context.display_step();

    let proof: P = P::deserialize_compressed(reader)?;

    Ok(proof)
}

impl std::fmt::Display for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.par {
            writeln!(f, "PCD Proof")?;
            writeln!(f, "compressible: {}", self.com)?;
            writeln!(
                f,
                "hash: {}, total nodes: {}, complete nodes: {}",
                self.hash, self.total_nodes, self.complete_nodes
            )?;
        }
        match self.proof {
            None => writeln!(f, "incomplete")?,
            Some(ref p) => {
                for x in p.iter().take(10) {
                    write!(f, "{:x} ", x)?;
                }
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

fn estimate_size(tr: &Trace) -> usize {
    use std::mem::size_of_val as sizeof;
    sizeof(tr)
        + tr.blocks.len()
            * (sizeof(&tr.blocks[0]) + tr.blocks[0].steps.len() * sizeof(&tr.blocks[0].steps[0]))
}

pub fn run(opts: &VMOpts, pow: bool) -> Result<Trace, ProofError> {
    let mut vm = load_nvm(opts)?;

    println!("Executing program...");

    let start = Instant::now();
    let trace = trace(&mut vm, opts.k, pow)?;

    println!(
        "Executed {} instructions in {:?}. {} bytes used by trace.",
        trace.k * trace.blocks.len(),
        start.elapsed(),
        estimate_size(&trace)
    );
    Ok(trace)
}

pub fn prove_seq(pp: &SeqPP, trace: Trace) -> Result<IVCProof, ProofError> {
    // let k = trace.k;
    let tr = Tr(trace);
    let icount = tr.instructions();
    let z_0 = tr.input(0)?;
    let mut proof = IVCProof::new(&z_0);

    let num_steps = tr.steps();

    let mut term = nexus_tui::TerminalHandle::new();
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

pub fn prove_par(pp: ParPP, trace: Trace) -> Result<PCDNode, ProofError> {
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

    let mut term = nexus_tui::TerminalHandle::new();
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

            let v = PCDNode::prove_leaf(&pp, &tr, i, &tr.input(i)?)?;
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
                let c = PCDNode::prove_parent(&pp, &tr, &ab[0], &ab[1])?;
                Ok(c)
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
    }

    Ok(vs.into_iter().next().unwrap())
}

pub fn prove_par_com(pp: ComPP, trace: Trace) -> Result<ComPCDNode, ProofError> {
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

    let mut term = nexus_tui::TerminalHandle::new();
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
            let v = ComPCDNode::prove_leaf(&pp, &tr, i, &tr.input(i)?)?;
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
                let c = ComPCDNode::prove_parent(&pp, &tr, &ab[0], &ab[1])?;
                Ok(c)
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
    }

    Ok(vs.into_iter().next().unwrap())
}

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
