use std::path::Path;

use reqwest::blocking::Client;

use crate::{Result, api::NexusAPI};
use crate::client::NexusAPI::{NexusProof, Error, Program, Query};
use nexus_prover::Proof;

#[cfg(debug_assertions)]
const URL: &str = "http://localhost:8080/api";
#[cfg(not(debug_assertions))]
const URL: &str = "http://35.209.216.211:80/api";

pub fn nexus_api(msg: &NexusAPI) -> Result<NexusAPI> {
    Ok(Client::new().post(URL).json(msg).send()?.json()?)
}

fn proof(msg: &NexusAPI) -> Result<Proof> {
    let msg = nexus_api(msg)?;
    match msg {
        NexusProof(p) => Ok(p),
        Error(m) => Err(m.into()),
        _ => Err("unexpected response".into()),
    }
}

pub fn submit_proof(account: String, path: &Path) -> Result<Proof> {
    let bytes = std::fs::read(path)?;
    let msg = Program { account, elf: bytes };
    proof(&msg)
}

pub fn fetch_proof(hash: &str) -> Result<Proof> {
    let msg = Query { hash: hash.to_string() };
    proof(&msg)
}
