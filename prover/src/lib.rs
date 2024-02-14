pub mod circuit;
pub mod error;
pub mod pp;
pub mod types;

use std::io::{self, Write};
use std::time::Instant;

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
    let k = trace.k;
    let tr = Tr(trace);
    let icount = tr.instructions();
    let z_0 = tr.input(0)?;
    let mut proof = IVCProof::new(pp, &z_0);

    println!("\nProving Execution Trace:");
    println!("step. {:7} {:8} {:32} time", "pc", "mem[pc]", "inst");

    let start = Instant::now();

    let num_steps = tr.steps();
    for i in 0..num_steps {
        print!("{:4}. {:51}", i, format!("{} instructions...", k));
        io::stdout().flush().unwrap();

        let t = Instant::now();
        proof = IVCProof::prove_step(proof, &tr)?;

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
    Ok(proof)
}

pub fn prove_par(pp: ParPP, trace: Trace) -> Result<PCDNode, ProofError> {
    let k = trace.k;
    let tr = Tr(trace);

    let steps = tr.steps();
    println!("\nproving {steps} steps...");

    let start = Instant::now();

    let mut vs = (0..steps)
        .step_by(2)
        .map(|i| {
            print!("leaf step {i}... ");
            io::stdout().flush().unwrap();
            let t = Instant::now();
            let v = PCDNode::prove_step(&pp, &tr, i, &tr.input(i)?)?;
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
    Ok(vs.into_iter().next().unwrap())
}
