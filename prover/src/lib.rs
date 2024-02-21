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
    // let k = trace.k;
    let tr = Tr(trace);
    let icount = tr.instructions();
    let z_0 = tr.input(0)?;
    let mut proof = IVCProof::new(pp, &z_0);

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
                "{num_steps} step(s) in {}; {:.2} instructions / second",
                nexus_tui::format_duration(elapsed),
                icount as f32 / elapsed.as_secs_f32()
            )
        });

    for _ in 0..num_steps {
        let _guard = term_ctx.display_step();

        proof = IVCProof::prove_step(proof, &tr)?;
    }

    {
        let mut term_ctx = term.context("Verifying").on_step(|_step| "proof".into());
        let _guard = term_ctx.display_step();
        proof.verify(num_steps).expect("verify"); // TODO add verify errors?
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
                "tree root in {}; {:.2} instructions / second",
                nexus_tui::format_duration(elapsed),
                (k * num_steps) as f32 / elapsed.as_secs_f32()
            )
        });

    let mut vs = (0..num_steps)
        .step_by(2)
        .map(|i| {
            let _guard = term_ctx.display_step();

            let v = PCDNode::prove_step(&pp, &tr, i, &tr.input(i)?)?;
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

                let c = PCDNode::prove_from(&pp, &tr, &ab[0], &ab[1])?;
                Ok(c)
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
    }

    {
        let mut term_ctx = term.context("Verifying").on_step(|_step| "root".into());
        let _guard = term_ctx.display_step();

        vs[0].verify(&pp)?;
    }

    Ok(vs.into_iter().next().unwrap())
}
