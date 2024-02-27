use nexus_prover::Proof;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum NexusAPI {
    Program { account: String, elf: Vec<u8> },
    Query { hash: String },
    NexusProof(Proof),
    Error(String),
}
