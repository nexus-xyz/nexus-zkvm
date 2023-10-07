use std::fs::File;
use zstd::stream::{Encoder, Decoder};
use nexus_riscv_circuit::k_step_circuit;

use crate::types::*;
use crate::error::*;
use crate::circuit::Tr;

/// On-disk format for public parameters
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PPDisk {
    pub ro_config: ROConfig,
    pub circuit1: R1CSShape<P1>,
    pub circuit2: R1CSShape<P2>,
    pub pp1: Vec<A1>,
    pub pp2: Vec<A2>,
    pub digest: F1,
}

pub fn gen_pp<T>(circuit: &T) -> Result<PP<T>, SynthesisError>
where
    T: StepCircuit<F1>,
{
    match PP::setup(ro_config(), circuit) {
        Ok(x) => Ok(x),
        Err(supernova::Error::R1CS(e)) => panic!("R1CS Error {e:?}"),
        Err(supernova::Error::Synthesis(e)) => Err(e),
    }
}

pub fn save_pp<T>(pp: PP<T>, file: &str) -> Result<(), ProofError> {
    let PublicParams {
        ro_config,
        shape,
        shape_secondary,
        pp,
        pp_secondary,
        digest,
        ..
    } = pp;

    #[allow(clippy::redundant_field_names)]
    let ppd = PPDisk {
        ro_config: ro_config,
        circuit1: shape,
        circuit2: shape_secondary,
        pp1: pp,
        pp2: pp_secondary,
        digest: digest,
    };

    let f = File::create(file)?;
    let mut enc = Encoder::new(&f, 0)?;
    ppd.serialize_compressed(&mut enc)?;
    enc.finish()?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp<T>(file: &str) -> Result<PP<T>, ProofError> {
    let f = File::open(file)?;
    let mut dec = Decoder::new(&f)?;
    let ppd: PPDisk = PPDisk::deserialize_compressed(&mut dec)?;

    Ok(PublicParams {
        ro_config: ppd.ro_config,
        shape: ppd.circuit1,
        shape_secondary: ppd.circuit2,
        pp: ppd.pp1,
        pp_secondary: ppd.pp2,
        digest: ppd.digest,
        _step_circuit: PhantomData,
    })
}

// -- VM specific versions

pub fn gen_vm_pp(k: usize) -> Result<PP<Tr>, ProofError> {
    let tr = Tr::new(k_step_circuit(k)?);
    let pp = gen_pp(&tr)?;
    Ok(pp)
}
