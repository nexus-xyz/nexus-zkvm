use std::sync::Arc;

use tokio::runtime::Handle;
use tokio::sync::{
    oneshot::{self, channel as oneshot},
    //   watch, OwnedSemaphorePermit as Permit, Semaphore, TryAcquireError,
};
//use tokio::time::{self, Duration};

use hyper::upgrade::Upgraded;

use async_channel::{unbounded, Receiver, Sender};

use nexus_core::prover::nova::{circuit::Tr, error::ProofError, types::*};

use nexus_network::pcd::*;
use nexus_network::*;

use crate::db::DB;

use anyhow;

#[derive(Clone)]
pub struct WorkerState {
    pub pp: Arc<ParPP>,
    pub pcd: (Sender<Work>, Receiver<Work>),
    pub msm: (Sender<Work>, Receiver<Work>),
    pub db: DB,
}

impl WorkerState {
    pub fn new(pp: ParPP) -> Self {
        Self {
            pp: Arc::new(pp),
            pcd: unbounded(),
            msm: unbounded(),
            db: DB::new(),
        }
    }
}

pub struct Work {
    pub msg: NexusMsg,
    pub response: oneshot::Sender<NexusMsg>,
}

fn send_response(ch: oneshot::Sender<NexusMsg>, msg: NexusMsg) -> Result<()> {
    ch.send(msg).map_err(|_| "oneshot send error")?;
    Ok(())
}

pub async fn request_work(ch: &Sender<Work>, msg: NexusMsg) -> Result<NexusMsg> {
    let (s, r) = oneshot();
    ch.send(Work { msg, response: s }).await?;
    Ok(r.await?)
}

/*
pub async fn request_work_timeout(ch: &Sender<Work>, msg: NexusMsg) -> Result<NexusMsg> {
    let sleep = time::sleep(Duration::from_secs(1));
    tokio::select! {
        res = request_work(ch, msg) => {
            res
        }
        _ = sleep => {
            Err("timeout".into())
        }
    }
}

pub async fn request_work_retry(ch: &Sender<Work>, msg: NexusMsg) -> Result<NexusMsg> {
    let mut count = 5;
    loop {
        match request_work_timeout(ch, msg.clone()).await {
            Ok(x) => return Ok(x),
            Err(e) => {
                eprintln!("{e}");
            }
        }
        count -= 1;
        if count <= 0 {
            break;
        }
    }
    Err("request failed".into())
}
*/

async fn chan_to_net(ch: Receiver<Work>, mut upg: Upgraded) -> Result<()> {
    loop {
        let Work { msg, response: ch } = ch.recv().await?;
        bin::write_msg(&mut upg, &msg).await?;
        let msg = bin::read_msg(&mut upg).await?;
        send_response(ch, msg)?;
    }
}

async fn net_to_chan(ch: Sender<Work>, mut upg: Upgraded) -> Result<()> {
    loop {
        let req: NexusMsg = bin::read_msg(&mut upg).await?;
        let res = request_work(&ch, req).await?;
        bin::write_msg(&mut upg, &res).await?;
    }
}

pub async fn msm_server_proxy(state: WorkerState, upg: Upgraded) -> Result<()> {
    let ch = state.msm.1.clone();
    chan_to_net(ch, upg).await
}

pub async fn msm_client_proxy(state: WorkerState, upg: Upgraded) -> Result<()> {
    let ch = state.msm.0.clone();
    net_to_chan(ch, upg).await
}

pub async fn pcd_server_proxy(state: WorkerState, upg: Upgraded) -> Result<()> {
    let ch = state.pcd.1.clone();
    chan_to_net(ch, upg).await
}

pub async fn pcd_client_proxy(state: WorkerState, upg: Upgraded) -> Result<()> {
    let ch = state.pcd.0.clone();
    net_to_chan(ch, upg).await
}

pub fn start_local_workers(state: WorkerState) -> Result<()> {
    let state2 = state.clone();
    let handle = Handle::current();
    std::thread::spawn(move || local_pcd(handle, state));
    std::thread::spawn(move || local_msm(state2));
    Ok(())
}

fn request_msm(rt: &Handle, state: &WorkerState, w: &R1CSWitness<P1>) -> P1 {
    tracing::trace!(
        target: LOG_TARGET,
        "sending MSM request",
    );
    // TODO eliminate clone
    let msg = MSMReq(w.W.clone());
    match rt.block_on(request_work(&state.msm.0, msg)) {
        Ok(MSMRes(p)) => p,
        _ => panic!("bad result"), // TODO this function cannot fail
    }
}

fn prove_leaf(
    rt: &Handle,
    st: &WorkerState,
    trace: Trace,
) -> std::result::Result<PCDNode, ProofError> {
    let i = trace.start;
    let tr = Tr(trace);
    tracing::trace!(
        target: LOG_TARGET,
        ?i,
        "proving leaf",
    );
    let node = PCDNode::prove_leaf_with_commit_fn(&st.pp, &tr, i, &tr.input(i)?, |_pp, w| {
        request_msm(rt, st, w)
    })?;
    Ok(node)
}

fn prove_node(
    rt: &Handle,
    st: &WorkerState,
    trace: Trace,
    l: PCDNode,
    r: PCDNode,
) -> std::result::Result<PCDNode, ProofError> {
    let tr = Tr(trace);
    let node =
        PCDNode::prove_parent_with_commit_fn(&st.pp, &tr, &l, &r, |_pp, w| request_msm(rt, st, w))?;
    Ok(node)
}

fn local_pcd(rt: Handle, state: WorkerState) -> Result<()> {
    loop {
        let Work { msg, response: ch } = state.pcd.1.recv_blocking()?;
        match msg {
            LeafReq(t) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "PCDLeaf start: {}, len: {}",
                    t.start,
                    t.blocks.len(),
                );
                let node = prove_leaf(&rt, &state, t)?;
                send_response(ch, PCDRes(node))?;
            }
            NodeReq(mut ns) => {
                // Verify we have exactly 2 nodes
                if ns.len() != 2 {
                    return Err(anyhow::anyhow!("Expected exactly 2 nodes, got {}", ns.len()));
                }
                let (r, _) = ns.pop().ok_or_else(|| anyhow::anyhow!("Failed to get right node"))?;
                let (l, lt) = ns.pop().ok_or_else(|| anyhow::anyhow!("Failed to get left node"))?;
                tracing::trace!(
                    target: LOG_TARGET,
                    "PCDNode {}-{}, {}-{} lts:{}",
                    l.i,
                    l.j,
                    r.i,
                    r.j,
                    lt.start,
                );

                let node = prove_node(&rt, &state, lt, l, r)?;
                send_response(ch, PCDRes(node))?;
            }
            _ => {
                tracing::error!(
                    target: LOG_TARGET,
                    "unexpected message in pcd-channel",
                );
            }
        }
    }
}

fn local_msm(state: WorkerState) -> Result<()> {
    loop {
        let Work { msg, response: ch } = state.msm.1.recv_blocking()?;
        match msg {
            MSMReq(fs) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "MSM F1 size {}",
                    fs.len(),
                );

                let res: P1 = C1::commit(&state.pp.pp, &fs);
                send_response(ch, MSMRes(res))?;
            }
            _ => {
                tracing::error!(
                    target: LOG_TARGET,
                    "unexpected message in msm-channel",
                );
            }
        }
    }
}
