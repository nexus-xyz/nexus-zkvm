pub mod circuit;
pub mod error;
pub mod pp;
pub mod types;

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

#[cfg(feature = "verbose")]
const TERMINAL_MODE: nexus_tui::Mode = nexus_tui::Mode::Enabled;
#[cfg(not(feature = "verbose"))]
const TERMINAL_MODE: nexus_tui::Mode = nexus_tui::Mode::Disabled;

const LOG_TARGET: &str = "nexus-prover";

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
