use serde::{Serialize, Deserialize};
use nexus_prover::Proof;

#[derive(Serialize, Deserialize)]
pub enum NexusAPI {
    Program { account: String, elf: Vec<u8> },
    Query { hash: String },
    NexusProof(Proof),
    Error(String),
}
