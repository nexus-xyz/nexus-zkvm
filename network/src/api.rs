use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub hash: String,
    pub total_nodes: u32,
    pub complete_nodes: u32,
    pub proof: Option<Vec<u8>>,
}

impl Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Hash: {}\nTotal Nodes: {}\nComplete Nodes: {}\n",
            self.hash, self.total_nodes, self.complete_nodes
        )?;
        
        match &self.proof {
            None => writeln!(f, "Proof: Incomplete")?,
            Some(ref p) => {
                let proof_hex = p.iter().take(10).map(|x| format!("{:x}", x)).collect::<Vec<String>>().join(" ");
                writeln!(f, "Proof (first 10 bytes): {}", proof_hex)?;
                if p.len() > 10 {
                    writeln!(f, "... (proof truncated)")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub enum NexusAPI {
    Program { account: String, elf: Vec<u8> },
    Query { hash: String },
    NexusProof(Proof),
    Error(NexusError),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NexusError {
    InvalidHashFormat(String),
    MissingData(String),
    InternalError(String),
}

impl Display for NexusAPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NexusAPI::Program { account, elf } => {
                write!(f, "Program: Account: {}, ELF size: {} bytes", account, elf.len())
            }
            NexusAPI::Query { hash } => write!(f, "Query for Hash: {}", hash),
            NexusAPI::NexusProof(proof) => write!(f, "Proof: {}", proof),
            NexusAPI::Error(error) => write!(f, "Error: {}", error),
        }
    }
}

impl Display for NexusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NexusError::InvalidHashFormat(ref details) => write!(f, "Invalid hash format: {}", details),
            NexusError::MissingData(ref details) => write!(f, "Missing data: {}", details),
            NexusError::InternalError(ref details) => write!(f, "Internal server error: {}", details),
        }
    }
}
