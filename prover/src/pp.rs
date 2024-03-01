use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::srs::load_srs;
use crate::circuit::{nop_circuit, Tr};
use crate::error::*;
use crate::types::*;
use crate::LOG_TARGET;

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
    let pp = PP::<C, SP>::deserialize_compressed(&mut dec)?;
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
    tracing::debug!(
        target: LOG_TARGET,
        "Primary circuit {}",
        pp.shape,
    );
    tracing::debug!(
        target: LOG_TARGET,
        "Secondary circuit {}",
        pp.shape_secondary,
    );
}

pub fn gen_to_file(
    k: usize,
    par: bool,
    pp_file: &str,
    srs_file: Option<&str>,
) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = ?pp_file,
        "Generating public parameters",
    );
    let mut term = nexus_tui::TerminalHandle::new();
    let mut term_ctx = term
        .context("Setting up")
        .on_step(|_step| "public parameters".into());
    let _guard = term_ctx.display_step();

    if par {
        match srs_file {
            Some(srs_file) => {
                let srs: SRS = load_srs(srs_file)?;
                let pp: ComPP = gen_vm_pp(k, &srs)?;
                show_pp(&pp);
                save_pp(pp, pp_file)
            }
            None => {
                let pp: ParPP = gen_vm_pp(k, &())?;
                show_pp(&pp);
                save_pp(pp, pp_file)
            }
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
    let mut term = nexus_tui::TerminalHandle::new();

    let pp: PP<C, SP> = if gen {
        tracing::info!(
            target: LOG_TARGET,
            "Generating public parameters",
        );
        let mut term_ctx = term
            .context("Setting up")
            .on_step(|_step| "public parameters".into());
        let _guard = term_ctx.display_step();

        gen_vm_pp(k, aux)?
    } else {
        tracing::info!(
            target: LOG_TARGET,
            path = ?pp_file,
            "Loading public parameters",
        );
        let mut term_ctx = term
            .context("Loading")
            .on_step(|_step| "public parameters".into());
        let _guard = term_ctx.display_step();

        load_pp(pp_file)?
    };
    drop(term);

    show_pp(&pp);
    Ok(pp)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::srs::test_srs::gen_test_srs_to_file;

    // This test will not pass unless we use the full 26-variable SRS
    #[test]
    #[ignore]
    fn test_gen_pp_with_srs() {
        gen_to_file(1, true, "test_pp.zst", Some("../test_srs.zst")).unwrap();
    }

    fn test_srs_gen() {
        gen_test_srs_to_file(10, "small_test_srs.zst").unwrap();
        let _srs: SRS = load_srs("small_test_srs.zst").unwrap();
    }

    #[test]
    #[ignore]
    fn test_load_srs() {
        test_srs_gen();
        let srs: SRS = load_srs("small_test_srs.zst").unwrap();
        println!("Loaded SRS for {} variables", srs.max_num_vars);
    }
}
