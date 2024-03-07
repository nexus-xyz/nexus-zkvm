use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub hash: String,
    pub total_nodes: u32,
    pub complete_nodes: u32,
    pub proof: Option<Vec<u8>>,
}

impl std::fmt::Display for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.hash, self.total_nodes, self.complete_nodes
        )?;
        match self.proof {
            None => writeln!(f, "incomplete")?,
            Some(ref p) => {
                for x in p.iter().take(10) {
                    write!(f, "{:x} ", x)?;
                }
                writeln!(f)?;
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
    Error(String),
}
