use std::fs::File;
use zstd::stream::{Encoder, Decoder};

pub use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use super::srs::load_srs;
use crate::types::*;
use crate::error::*;
use crate::circuit::{Tr, nop_circuit};

pub fn gen_pp<C, SP>(circuit: &SC, aux: &C::SetupAux) -> Result<PP<C, SP>, ProofError>
where
    C: CommitmentScheme<P1>,
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
{
    Ok(SP::setup(ro_config(), circuit, aux, &())?)
}

pub fn save_pp<C, SP>(pp: PP<C, SP>, file: &str) -> Result<(), ProofError>
where
    C: CommitmentScheme<P1>,
    SC: StepCircuit<F1>,
    SP: SetupParams<G1, G2, C, C2, RO, SC>,
{
    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    pp.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp<C, SP>(file: &str) -> Result<PP<C, SP>, ProofError>
where
    C: CommitmentScheme<P1>,
    SC: StepCircuit<F1> + Sync,
    SP: SetupParams<G1, G2, C, C2, RO, SC> + Sync,
{
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PP::<C, SP>::deserialize_compressed_unchecked(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp<C, SP>(k: usize, aux: &C::SetupAux) -> Result<PP<C, SP>, ProofError>
where
    SP: SetupParams<G1, G2, C, C2, RO, Tr>,
    C: CommitmentScheme<P1>,
{
    let tr = nop_circuit(k)?;
    gen_pp(&tr, aux)
}

fn show_pp<C, SP>(pp: &PP<C, SP>)
where
    SP: SetupParams<G1, G2, C, C2, RO, Tr>,
    C: CommitmentScheme<P1>,
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

pub fn gen_to_file(
    k: usize,
    par: bool,
    com: bool,
    pp_file: &str,
    srs_file: Option<&str>,
) -> Result<(), ProofError> {
    println!("Generating public parameters to {pp_file}...");
    if par {
        if com {
            let srs_file = srs_file.ok_or(ProofError::MissingSRS)?;
            println!("Loading SRS from {srs_file}...");
            let srs: SRS = load_srs(srs_file)?;
            println!("Loaded SRS for {} variables", srs.max_num_vars);
            let pp: ComPP = gen_vm_pp(k, &srs)?;
            show_pp(&pp);
            save_pp(pp, pp_file)
        } else {
            let pp: ParPP = gen_vm_pp(k, &())?;
            show_pp(&pp);
            save_pp(pp, pp_file)
        }
    } else {
        let pp: SeqPP = gen_vm_pp(k, &())?;
        show_pp(&pp);
        save_pp(pp, pp_file)
    }
}

pub fn gen_or_load<C, SP>(
    gen: bool,
    k: usize,
    pp_file: &str,
    aux: &C::SetupAux,
) -> Result<PP<C, SP>, ProofError>
where
    SP: SetupParams<G1, G2, C, C2, RO, Tr> + Sync,
    C: CommitmentScheme<P1>,
{
    let t = std::time::Instant::now();
    let pp: PP<C, SP> = if gen {
        println!("Generating public parameters...");
        gen_vm_pp(k, aux)?
    } else {
        println!("Loading public parameters from {pp_file}...");
        load_pp(pp_file)?
    };
    println!("Got public parameters in {:?}", t.elapsed());
    show_pp(&pp);
    Ok(pp)
}

#[cfg(test)]
mod test {
    use crate::srs::test_srs::gen_test_srs_to_file;
    use super::*;

    #[test]
    fn test_gen_pp_with_srs() {
        gen_to_file(1, true, true, "test_pp.zst", Some("../test_srs.zst")).unwrap();
    }

    #[test]
    fn test_srs_gen() {
        gen_test_srs_to_file(10, "small_test_srs.zst").unwrap();
        let _srs: SRS = load_srs("small_test_srs.zst").unwrap();
    }

    #[test]
    fn test_load_srs() {
        let srs: SRS = load_srs("../test_srs.zst").unwrap();
        println!("Loaded SRS for {} variables", srs.max_num_vars);
    }
}
