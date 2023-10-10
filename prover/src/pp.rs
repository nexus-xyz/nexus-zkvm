use std::fs::File;
use zstd::stream::{Encoder, Decoder};
use nexus_riscv_circuit::k_step_circuit;

use crate::types::*;
use crate::error::*;
use crate::circuit::Tr;

use supernova::nova::public_params::SetupParams;

pub fn gen_pp<SP, SC>(circuit: &SC) -> Result<PP<SP, SC>, ProofError>
where
    SC: StepCircuit<F1>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    Ok(SP::setup(ro_config(), circuit)?)
}

pub fn save_pp<SC, SP>(pp: PP<SP, SC>, file: &str) -> Result<(), ProofError>
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

pub fn load_pp<SP, SC>(file: &str) -> Result<PP<SP, SC>, ProofError>
where
    SC: StepCircuit<F1> + Sync,
    SP: SetupParams<G1, G2, C1, C2, RO, SC> + Sync,
{
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::<SP, SC>::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

// -- VM specific versions

pub fn gen_vm_pp<SP>(k: usize) -> Result<PP<SP, Tr>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr>,
{
    let tr = Tr::new(k_step_circuit(k)?);
    gen_pp(&tr)
}

pub fn gen_or_load<SP>(gen: bool, k: usize, pp_file: &str) -> Result<PP<SP, Tr>, ProofError>
where
    SP: SetupParams<G1, G2, C1, C2, RO, Tr> + Sync,
{
    let t = std::time::Instant::now();
    let pp: PP<SP, Tr> = if gen {
        println!("Generating public parameters...");
        gen_vm_pp(k)?
    } else {
        println!("Loading public parameters from {pp_file}...");
        load_pp(pp_file)?
    };
    println!("Got public parameters in {:?}", t.elapsed());
    println!(
        "Primary Circuit {} x {}",
        pp.shape.num_vars, pp.shape.num_constraints
    );
    println!(
        "Secondary Circuit {} x {}",
        pp.shape_secondary.num_vars, pp.shape_secondary.num_constraints
    );
    Ok(pp)
}
