pub mod error;
pub mod types;
pub mod circuit;
pub mod pp;
pub mod srs;

use std::time::Instant;
use std::io::{self, Write};
use error::ProofError;
use nexus_riscv::{
    VMOpts, load_vm,
    vm::trace::{Trace, trace},
};

use serde::{Serialize, Deserialize};
use supernova::nova::pcd::compression::SNARK;
use types::{ComPP, ParPP, SeqPP, SRS};

use crate::circuit::Tr;
use crate::types::{IVCProof, PCDNode, ComPCDNode};
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
    let mut vm = load_vm(opts)?;

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

pub fn prove_seq(pp: SeqPP, trace: Trace) -> Result<Proof, ProofError> {
    let k = trace.k;
    let tr = Tr::new(trace);
    let icount = tr.instructions();
    let z_0 = tr.input(0);
    let mut proof = IVCProof::new(&pp, &z_0);

    println!("\nProving Execution Trace:");
    println!("step. {:7} {:8} {:32} time", "pc", "mem[pc]", "inst");

    let start = Instant::now();

    let num_steps = tr.steps();
    for i in 0..num_steps {
        print!("{:4}. {:51}", i, format!("{} instructions...", k));
        io::stdout().flush().unwrap();

        let t = Instant::now();
        proof = IVCProof::prove_step(proof, &tr).unwrap();

        println!(
            "{:?}  {:0.2}%",
            t.elapsed(),
            ((i + 1) as f32) * 100.0 / (num_steps as f32)
        );
    }
    println!(
        "\nProof Complete: {:.2} instructions / second",
        icount as f64 / start.elapsed().as_secs_f64()
    );

    print!("\nVerifying Proof... ");
    io::stdout().flush().unwrap();
    let t = Instant::now();
    proof.verify(num_steps).expect("verify"); // TODO add verify errors?
    println!("{:?}", t.elapsed());

    Ok(Proof::default())
}

pub fn prove_par(pp: ParPP, trace: Trace) -> Result<Proof, ProofError> {
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
            let v = PCDNode::prove_step(&pp, &tr, i, &tr.input(i))?;
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
    compression_pp: ComPP,
    compression_srs: SRS,
    proof: Proof,
    local: bool,
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

    let key = SNARK::setup(&compression_pp, &compression_srs).unwrap();
    // TODO: save key to file and add an option to load the key

    let compressed_pcd_proof = SNARK::compress(&compression_pp, &key, node).unwrap();

    // And check that the compressed proof verifies.
    SNARK::verify(&key, &compression_pp, &compressed_pcd_proof).unwrap();

    // TODO: save compressed proof to file

    Ok(())
}

/* cursed enum matching below
pub fn prove_par(pp: PPEnum, trace: Trace) -> Result<Proof, ProofError> {
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
            let v = match &pp {
                PPEnum::Com(par) => {
                    NodeEnum::Com(ComPCDNode::prove_step(&par, &tr, i, &tr.input(i))?)
                },

                PPEnum::NoCom(par) => {
                    NodeEnum::NoCom(PCDNode::prove_step(&par, &tr, i, &tr.input(i))?)
                }
            };
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
            .map(|_| {
                print!("vertex step ...  ");
                io::stdout().flush().unwrap();
                let t = Instant::now();
                let c = match &pp {
                    PPEnum::Com(par) => {
                        match &vs[0] {
                            NodeEnum::Com(v) => {
                                match &vs[1] {
                                    NodeEnum::Com(w) => {
                                        NodeEnum::Com(ComPCDNode::prove_from(&par, &tr, &v, &w)?)
                                    },
                                    NodeEnum::NoCom(_) => {
                                        panic!("should never get here")
                                    }
                                }
                            },
                            NodeEnum::NoCom(_) => {
                                match &vs[1] {
                                    NodeEnum::Com(_) => {
                                        panic!("should never get here")
                                    },
                                    NodeEnum::NoCom(_) => {
                                        panic!("should never get here")
                                    }
                                }
                            }
                        }
                    },

                    PPEnum::NoCom(par) => {
                        match &vs[0] {
                            NodeEnum::Com(_) => {
                                match &vs[1] {
                                    NodeEnum::Com(_) => {
                                        panic!("should never get here")
                                    },
                                    NodeEnum::NoCom(_) => {
                                        panic!("should never get here")
                                    }
                                }
                            },
                            NodeEnum::NoCom(v) => {
                                match &vs[1] {
                                    NodeEnum::Com(_) => {
                                        panic!("should never get here")
                                    },
                                    NodeEnum::NoCom(w) => {
                                        NodeEnum::NoCom(PCDNode::prove_from(&par, &tr, &v, &w)?)
                                    }
                                }
                            }
                        }

                    }
                };
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
    match &vs[0] {
        NodeEnum::Com(v) => {
            match &pp {
                PPEnum::Com(pp) => v.verify(&pp)?,
                PPEnum::NoCom(_) => panic!("Trying to verify compressed proof with non compression parameters")
            }
        },
        NodeEnum::NoCom(v) => {
            match &pp {
                PPEnum::Com(_) => panic!("Trying to verify non compressed proof with compression parameters"),
                PPEnum::NoCom(pp) => v.verify(&pp)?
            }
        }
    };
    println!("{:?}", t.elapsed());

    let mut proof_bytes = Vec::new();

    match &vs[0] {
        NodeEnum::Com(v) => v.serialize_compressed(&mut proof_bytes)?,
        NodeEnum::NoCom(v) => v.serialize_compressed(&mut proof_bytes)?
    };

    let proof = Proof {
        hash: "test".to_string(),
        total_nodes: vs.len() as u32,
        complete_nodes: vs.len() as u32,
        proof: Some(proof_bytes),
    };

    Ok(proof)
}
*/
