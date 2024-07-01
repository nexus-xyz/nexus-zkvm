use std::path::PathBuf;

use nexus_core::config::{
    vm::{NovaImpl, ProverImpl, VmConfig},
    Config, MiscConfig,
};
use nexus_core::nvm::{
    interactive::{parse_elf, trace},
    memory::MerkleTrie,
};
use nexus_core::prover::nova::types::{IVCProof, SeqPP};
use nexus_rpc_common::ElfBytes;

use super::{Error, ProverT};

const NOVA_IMPL: NovaImpl = NovaImpl::Sequential;
const CONFIG: VmConfig = VmConfig {
    k: 16,
    prover: ProverImpl::Nova(NOVA_IMPL),
};

const LOG_TARGET: &str = "nexus-rpc::nova";

pub struct NovaProver;

impl ProverT for NovaProver {
    type Proof = IVCProof;
    type Params = SeqPP;

    fn prove(pp: &SeqPP, elf_bytes: ElfBytes) -> Result<Self::Proof, Error> {
        let mut vm = parse_elf(&elf_bytes)?;

        let trace = trace::<MerkleTrie>(&mut vm, CONFIG.k, false)?;
        let proof = nexus_core::prover::nova::prove_seq(pp, trace).map_err(Error::Nova)?;

        Ok(proof)
    }
}

pub fn load_params() -> SeqPP {
    let _span = tracing::info_span!(
        target: LOG_TARGET,
        "load_params",
        k = CONFIG.k,
        nova_impl = ?NOVA_IMPL,
    )
    .entered();

    let path = cache_path().join(format_params_file(NOVA_IMPL, CONFIG.k));
    let path_str = path.to_str().expect("cache path is not valid utf8");

    if path.exists() {
        nexus_core::prover::nova::pp::load_pp(path_str).expect("failed to load params")
    } else {
        let _span = tracing::info_span!(
            target: LOG_TARGET,
            "gen_params",
            k = CONFIG.k,
            nova_impl = ?NOVA_IMPL,
        )
        .entered();

        let pp: SeqPP = nexus_core::prover::nova::pp::gen_vm_pp(CONFIG.k, &())
            .expect("failed to gen parameters");
        nexus_core::prover::nova::pp::save_pp(&pp, path_str).expect("failed to save parameters");
        pp
    }
}

pub fn format_params_file(nova_impl: NovaImpl, k: usize) -> String {
    format!("nexus-public-{nova_impl}-{k}.zst")
}

/// Creates and returns the cache path.
pub(crate) fn cache_path() -> PathBuf {
    let path = if let Ok(config) = MiscConfig::from_env() {
        config.cache
    } else {
        // default to using project target directory
        const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target");
        PathBuf::from(PATH).join("nexus-cache")
    };
    std::fs::create_dir_all(&path).expect("failed to create cache dir");

    path
}
