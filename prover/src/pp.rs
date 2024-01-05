use std::fs::File;
use zstd::stream::{Encoder, Decoder};

pub use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::types::*;
use crate::error::*;
use crate::circuit::{Tr, nop_circuit};

pub fn gen_pp<SP>(circuit: &SC) -> Result<PP<SP>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    Ok(SP::setup(ro_config(), circuit, &(), &())?)
}

pub fn save_pp<SP>(pp: PP<SP>, file: &str) -> Result<(), ProofError>
where
    SC: StepCircuit<F1>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    pp.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp<SP>(file: &str) -> Result<PP<SP>, ProofError>
where
    SC: StepCircuit<F1> + Sync,
    SP: SetupParams<G1, G2, C1, C2, RO, SC> + Sync,
{
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::<SP>::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp<SP>(k: usize) -> Result<PP<SP>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr>,
{
    let tr = nop_circuit(k)?;
    gen_pp(&tr)
}

fn show_pp<SP>(pp: &PP<SP>)
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr>,
{
    println!(
        "Primary Circuit {} vars x {} constraints, {} io",
        pp.shape.num_vars, pp.shape.num_constraints, pp.shape.num_io
    );
    println!(
        "Secondary Circuit {} vars x {} constraints, {} io",
        pp.shape_secondary.num_vars, pp.shape_secondary.num_constraints, pp.shape_secondary.num_io
    );
}

pub fn gen_to_file(k: usize, par: bool, pp_file: &str) -> Result<(), ProofError> {
    println!("Generating public parameters to {pp_file}...");
    if par {
        let pp: ParPP = gen_vm_pp(k)?;
        show_pp(&pp);
        save_pp(pp, pp_file)
    } else {
        let pp: SeqPP = gen_vm_pp(k)?;
        show_pp(&pp);
        save_pp(pp, pp_file)
    }
}

pub fn gen_or_load<SP>(gen: bool, k: usize, pp_file: &str) -> Result<PP<SP>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr> + Sync,
{
    let t = std::time::Instant::now();
    let pp: PP<SP> = if gen {
        println!("Generating public parameters...");
        gen_vm_pp(k)?
    } else {
        println!("Loading public parameters from {pp_file}...");
        load_pp(pp_file)?
    };
    println!("Got public parameters in {:?}", t.elapsed());
    show_pp(&pp);
    Ok(pp)
}
