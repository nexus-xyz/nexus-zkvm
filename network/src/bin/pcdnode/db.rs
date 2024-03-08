use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::Proof;

#[derive(Clone, Default)]
pub struct DB(Arc<Mutex<DBase>>);

#[derive(Default)]
pub struct DBase {
    proofs: HashMap<String, Proof>,
}

impl DB {
    pub fn new() -> Self {
        DB(Arc::new(Mutex::new(DBase { proofs: HashMap::new() })))
    }

    pub fn new_proof(&mut self, hash: String, total: u32) {
        let mut db = self.0.lock().unwrap();
        let proof = db.proofs.entry(hash.clone()).or_default();
        proof.hash = hash;
        proof.total_nodes = total;
    }

    pub fn query_proof(&mut self, hash: &str) -> Option<Proof> {
        let db = self.0.lock().unwrap();
        db.proofs.get(hash).cloned() // TODO eliminate clone
    }

    pub fn update_complete(&mut self, hash: String, complete: u32) {
        let mut db = self.0.lock().unwrap();
        db.proofs
            .entry(hash)
            .and_modify(|p| p.complete_nodes += complete);
    }

    pub fn update_proof(&mut self, hash: String, proof: Vec<u8>) {
        let mut db = self.0.lock().unwrap();
        db.proofs.entry(hash).and_modify(|p| p.proof = Some(proof));
    }
}
