use std::collections::VecDeque;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use hyper::{header, Body, Request, Response, StatusCode};
use tokio::task::JoinHandle;

use nexus_network::api::*;
use nexus_network::pcd::*;
use nexus_network::*;
use nexus_vm::{eval::NexusVM, riscv::translate_elf_bytes, trace::trace};

use crate::workers::*;

pub fn manage_proof(mut state: WorkerState, hash: String, mut vm: NexusVM) -> Result<()> {
    let trace = Arc::new(trace(&mut vm, 1, true)?);

    let steps = trace.blocks.len() as u32;
    state.db.new_proof(hash.clone(), steps - 1);
    let hash = Arc::new(hash);

    let t = std::time::Instant::now();
    tracing::debug!(
        target: LOG_TARGET,
        steps = trace.blocks.len(),
        "starting computing the proof",
    );

    let mut v: VecDeque<JoinHandle<NexusMsg>> = VecDeque::with_capacity(trace.blocks.len() / 2);

    for t in trace.split_by(2) {
        let ch = state.pcd.0.clone();
        let jh = tokio::spawn(async move { request_work(&ch, LeafReq(t)).await.unwrap() });
        v.push_back(jh);
    }

    loop {
        if v.len() == 1 {
            let mut state = state.clone();
            let hash = hash.clone();
            tokio::spawn(async move {
                let proof = v.pop_front().unwrap().await.unwrap();
                state.db.update_complete(hash.to_string(), 1);
                tracing::info!(
                    target: LOG_TARGET,
                    elapsed = ?t.elapsed(),
                    "proof complete, verifying",
                );

                let PCDRes(ref node) = proof else { panic!() };
                node.verify(&state.pp).unwrap();

                tracing::info!(
                    target: LOG_TARGET,
                    "proof OK",
                );
                // at this point we store the proof so user
                // can get it later
                let proof: Vec<u8> = encode(&proof).unwrap();
                state.db.update_proof(hash.to_string(), proof);
            });
            break;
        }

        let mut v2: VecDeque<JoinHandle<NexusMsg>> = VecDeque::with_capacity(v.len() / 2);
        for _ in 0..v.len() / 2 {
            let mut state = state.clone();
            let hash = hash.clone();
            let ch = state.pcd.0.clone();
            let l = v.pop_front().unwrap();
            let r = v.pop_front().unwrap();
            let trace = trace.clone();
            v2.push_back(tokio::spawn(async move {
                let PCDRes(l) = l.await.unwrap() else { panic!() };
                let PCDRes(r) = r.await.unwrap() else { panic!() };
                state.db.update_complete(hash.to_string(), 2);
                let ltr = trace.get(l.j as usize).unwrap();
                let rtr = trace.get(r.j as usize).unwrap();
                let req = NodeReq(vec![(l, ltr), (r, rtr)]);
                request_work(&ch, req).await.unwrap()
            }));
        }
        v = v2;
    }
    Ok(())
}

fn api(mut state: WorkerState, msg: NexusAPI) -> Result<NexusAPI> {
    match msg {
        Program { elf, .. } => {
            tracing::info!(
                target: LOG_TARGET,
                "received prove-request",
            );
            let vm = translate_elf_bytes(&elf)?;
            let hash = hex::encode(Sha256::digest(&elf));
            manage_proof(state, hash.clone(), vm)?;
            Ok(Proof(Proof { hash, ..Proof::default() }))
        }
        Query { hash } => {
            tracing::info!(
                target: LOG_TARGET,
                "received proof-query",
            );
            let proof = state.db.query_proof(&hash);
            match proof {
                None => Err("proof not found".into()),
                Some(p) => Ok(Proof(p)),
            }
        }
        _ => Err("Invalid Message".into()),
    }
}

pub async fn post_api(state: WorkerState, req: Request<Body>) -> Result<Response<Body>> {
    let whole_body = hyper::body::to_bytes(req).await?;
    let msg: NexusAPI = serde_json::from_slice(&whole_body)?;

    let res = api(state, msg).unwrap_or_else(|e| Error(e.to_string()));

    let json = serde_json::to_vec(&res)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json.into())?;
    Ok(response)
}
