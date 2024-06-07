#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

mod db;
mod post;
mod workers;

use std::net::SocketAddr;

use clap::Parser;

use http::uri;
use hyper::{
    header::UPGRADE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use tracing_subscriber::EnvFilter;

use nexus_api::prover::nova::pp::gen_or_load;

use nexus_network::*;
use post::*;
use workers::*;

fn r404() -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("not found".into())?)
}

async fn router(state: WorkerState, req: Request<Body>) -> Result<Response<Body>> {
    if let Some(proto) = req.headers().get(UPGRADE) {
        let proto = proto.to_str()?;
        match (proto, req.uri().path()) {
            ("nexus", "/msm") => return bin::upgrade(state, req, msm_server_proxy),
            ("nexus", "/pcd") => return bin::upgrade(state, req, pcd_server_proxy),
            _ => return r404(),
        }
    }

    if req.method() == Method::POST {
        match req.uri().path() {
            "/api" => return post_api(state, req).await,
            _ => return r404(),
        }
    }

    r404()
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Act as coordinator node
    #[arg(group = "type", short)]
    well_known: bool,

    /// Act as PCD prover node
    #[arg(group = "type", short)]
    pcd: bool,

    /// Act as MSM prover node
    #[arg(group = "type", short)]
    msm: bool,

    #[arg(short, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    #[arg(short, default_value = "127.0.0.1:8080")]
    connect: uri::Authority,

    /// public parameters file
    #[arg(long = "public-params", default_value = "nexus-public.zst")]
    pp_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_env_filter(filter)
        .init();

    let opts = Opts::parse();

    let pp = gen_or_load(false, 0, &opts.pp_file, None)?;
    let state = WorkerState::new(pp);

    start_local_workers(state.clone())?;

    if opts.msm {
        bin::client(state.clone(), &opts.connect, "msm", msm_client_proxy).await?;
    }
    if opts.pcd {
        bin::client(state.clone(), &opts.connect, "pcd", pcd_client_proxy).await?;
    } else {
        let new_service = make_service_fn(move |_| {
            let state = state.clone();
            async move {
                let f = service_fn(move |req| {
                    let state = state.clone();
                    router(state, req)
                });
                Ok::<_, DynError>(f)
            }
        });

        let server = Server::bind(&opts.listen)
            .tcp_keepalive(Some(core::time::Duration::from_secs(20)))
            .tcp_nodelay(true)
            .serve(new_service);

        tracing::info!(
            target: LOG_TARGET,
            "Listening on http://{}",
            server.local_addr(),
        );

        server.await?;
    }
    Ok(())
}
