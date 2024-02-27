pub mod circuit;
pub mod error;
pub mod key;
pub mod pp;
pub mod srs;

use std::fs::File;
use std::time::Instant;
pub mod types;

use error::ProofError;
use std::io::{self, Write};
use zstd::stream::Encoder;

use nexus_vm::{
    riscv::{load_nvm, VMOpts},
    trace::{trace, Trace},
};

use crate::{
    circuit::Tr,
    error::ProofError,
    types::{IVCProof, PCDNode, ParPP, SeqPP},
};

const LOG_TARGET: &str = "nexus-prover";

use serde::{Deserialize, Serialize};
use supernova::nova::pcd::compression::SNARK;
use types::{ComPP, ParPP, SeqPP, SpartanKey};

use crate::circuit::Tr;
use crate::types::{ComPCDNode, IVCProof, PCDNode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub hash: String,
    pub total_nodes: u32,
    pub complete_nodes: u32,
    pub proof: Option<Vec<u8>>,
}

pub fn load_proof(file: &str) -> Result<Proof, ProofError> {
    let file = std::fs::File::open(file)?;
    let reader = std::io::BufReader::new(file);
    let proof: Proof = serde_json::from_reader(reader).unwrap();

    Ok(proof)
}

impl std::fmt::Display for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.hash, self.total_nodes, self.complete_nodes
        )?;
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

    let start = Instant::now();
    println!("Executing program...");
    println!("\n---vvv--- program output, if any ---vvv---");
    io::stdout().flush().unwrap();

    let trace = trace(&mut vm, opts.k, pow)?;
    println!("\n---^^^--- program output, if any ---^^^---\n");

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
            print!("leaf step {i}... ");
            io::stdout().flush().unwrap();
            let t = Instant::now();
            let v = PCDNode::prove_step(&pp, &tr, i, &tr.input(i))?;
            println!("{:?}", t.elapsed());
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
                print!("vertex step ...  ");
                io::stdout().flush().unwrap();
                let t = Instant::now();
                let c = PCDNode::prove_from(&pp, &tr, &ab[0], &ab[1])?;
                println!("{:?}", t.elapsed());
                Ok(c)
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
    }

    println!(
        "\nProof Complete: {:.2} instructions / second",
        (k * tr.steps()) as f64 / start.elapsed().as_secs_f64()
    );

    print!("\nVerifying root...  ");
    io::stdout().flush().unwrap();
    let t = Instant::now();
    vs[0].verify(&pp)?;
    println!("{:?}", t.elapsed());

    let mut proof_bytes = Vec::new();
    vs[0].serialize_compressed(&mut proof_bytes)?;

    let proof = Proof {
        hash: "test".to_string(),
        total_nodes: vs.len() as u32,
        complete_nodes: vs.len() as u32,
        proof: Some(proof_bytes),
    };

    Ok(proof)
}

pub fn prove_par_com(pp: ComPP, trace: Trace) -> Result<Proof, ProofError> {
    let k = trace.k;
    let tr = Tr::new(trace);

    let steps = tr.steps();
    println!("\nproving {steps} steps...");

    let start = Instant::now();

    let mut vs = (0..steps)
        .step_by(2)
        .map(|i| {
            print!("leaf step {i}... ");
            io::stdout().flush().unwrap();
            let t = Instant::now();
            let v = ComPCDNode::prove_step(&pp, &tr, i, &tr.input(i))?;
            println!("{:?}", t.elapsed());
            Ok(v)
        })
        .collect::<Result<Vec<_>, ProofError>>()?;

    loop {
        if vs.len() == 1 {
            break;
        }
        println!("proving {} vertex steps", vs.len() / 2);
        vs = vs
            .chunks(2)
            .map(|ab| {
                print!("vertex step ...  ");
                io::stdout().flush().unwrap();
                let t = Instant::now();
                let c = ComPCDNode::prove_from(&pp, &tr, &ab[0], &ab[1])?;
                println!("{:?}", t.elapsed());
                Ok(c)
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
    }

    println!(
        "\nProof Complete: {:.2} instructions / second",
        (k * tr.steps()) as f64 / start.elapsed().as_secs_f64()
    );

    print!("\nVerifying root...  ");
    io::stdout().flush().unwrap();
    let t = Instant::now();
    vs[0].verify(&pp)?;
    println!("{:?}", t.elapsed());

    let mut proof_bytes = Vec::new();
    vs[0].serialize_compressed(&mut proof_bytes)?;

    let proof = Proof {
        hash: "test".to_string(),
        total_nodes: vs.len() as u32,
        complete_nodes: vs.len() as u32,
        proof: Some(proof_bytes),
    };

    Ok(proof)
}

pub fn compress(
    compression_pp: &ComPP,
    key: &SpartanKey,
    proof: Proof,
    local: bool,
    compressed_proof_file: &str,
) -> Result<(), ProofError> {
    let Some(vec) = proof.proof else {
        todo!("handle error better")
    };

    let node: ComPCDNode;

    if local {
        println!("doing local verify");
        let tmp = supernova::nova::pcd::PCDNode::deserialize_compressed(&*vec);
        match tmp {
            Ok(n) => node = n,
            Err(e) => return Err(ProofError::SerError(e)),
        };
    } else {
        unimplemented!()
    };

    let compressed_pcd_proof = SNARK::compress(compression_pp, key, node).unwrap();

    // And check that the compressed proof verifies.
    SNARK::verify(key, compression_pp, &compressed_pcd_proof).unwrap();

    // Save compressed proof to file.
    let f = File::create(compressed_proof_file)?;
    let mut enc = Encoder::new(&f, 0)?;
    compressed_pcd_proof.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;

    Ok(())
}
