use std::fs::File;
use zstd::stream::{Decoder, Encoder};

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldElementSize};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};

use nexus_nova::nova::public_params::{PublicParams, SetupParams};
use nexus_nova::{commitment::CommitmentScheme, StepCircuit};

use super::srs::load_srs;
use crate::prover::nova::circuit::{nop_circuit, Tr};
use crate::prover::nova::error::*;
use crate::prover::nova::LOG_TARGET;

pub fn gen_pp<G1, G2, C1, C2, RO, SC, SP>(
    circuit: &SC,
    aux: &C1::SetupAux,
) -> Result<PublicParams<G1, G2, C1, C2, RO, SC, SP>, ProofError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    tracing::info!(
        target: LOG_TARGET,
        "Generating public parameters",
    );

    Ok(SP::setup(RO::Config(), circuit, aux, &())?)
}

pub fn save_pp<G1, G2, C1, C2, RO, SC, SP>(
    pp: PublicParams<G1, G2, C1, C2, RO, SC, SP>,
    file: &str
) -> Result<(), ProofError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    tracing::info!(
        target: LOG_TARGET,
        path = ?file,
        "Saving public parameters",
    );

    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    pp.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp<G1, G2, C1, C2, RO, SC, SP>(
    file: &str
) -> Result<PublicParams<G1, G2, C1, C2, RO, SC, SP>, ProofError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    tracing::info!(
        target: LOG_TARGET,
        path = ?file,
        "Loading public parameters",
    );

    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let pp = PublicParams::<G1, G2, C1, C2, RO, SC, SP>::deserialize_compressed(&mut dec)?;
    Ok(pp)
}

pub fn gen_vm_pp<G1, G2, C1, C2, RO, SC, SP>(
    k: usize,
    aux: &C1::SetupAux,
) -> Result<PublicParams<G1, G2, C1, C2, RO, SC, SP>, ProofError>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
{
    let tr = nop_circuit(k)?;
    gen_pp(&tr, aux)
}

pub fn show_pp<G1, G2, C1, C2, RO, SC, SP>(
    pp: &PublicParams<G1, G2, C1, C2, RO, SC, SP>
) -> ()
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
    SP: SetupParams<G1, G2, C1, C2, RO, SC>,
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
    srs_file_opt: Option<&str>,
) -> Result<(), ProofError> {
    tracing::info!(
        target: LOG_TARGET,
        path = ?pp_file,
        "Generating public parameters",
    );
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);

    if par {
        match srs_file_opt {
            Some(srs_file) => {
                tracing::info!(
                target: LOG_TARGET,
                path =?srs_file,
                "Reading the SRS",
                );
                let srs: SRS = {
                    let mut term_ctx = term.context("Loading").on_step(|_step| "SRS".into());
                    let _guard = term_ctx.display_step();
                    load_srs(srs_file)?
                };
                tracing::info!(
                    target: LOG_TARGET,
                    path =?srs_file,
                    "SRS found for a maximum of {} variables",
                    srs.max_num_vars
                );
                let pp: ComPP = {
                    tracing::info!(
                        target: LOG_TARGET,
                        "Generating compressible PCD public parameters",
                    );
                    let mut term_ctx = term
                        .context("Setting up")
                        .on_step(|_step| "public parameters for PCD (compression enabled)".into());
                    let _guard = term_ctx.display_step();
                    gen_vm_pp(k, &srs)?
                };

                show_pp(&pp);
                save_pp(pp, pp_file)
            }
            None => {
                tracing::info!(
                    target: LOG_TARGET,
                    "Generating non-compressible PCD public parameters",
                );
                let pp: ParPP = {
                    let mut term_ctx = term
                        .context("Setting up")
                        .on_step(|_step| "public parameters for PCD (compression disabled)".into());
                    let _guard = term_ctx.display_step();

                    gen_vm_pp(k, &())?
                };
                show_pp(&pp);
                save_pp(pp, pp_file)
            }
        }
    } else {
        tracing::info!(
            target: LOG_TARGET,
            "Generating IVC public parameters",
        );

        let pp: SeqPP = {
            let mut term_ctx = term
                .context("Setting up")
                .on_step(|_step| "public parameters for IVC".into());
            let _guard = term_ctx.display_step();
            gen_vm_pp(k, &())?
        };
        show_pp(&pp);
        save_pp(pp, pp_file)
    }
}
