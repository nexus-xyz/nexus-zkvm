#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

mod workers;
mod post;
mod db;

use std::net::SocketAddr;

use clap::Parser;

use hyper::{
    header::{self, UPGRADE},
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};

use nexus_prover::pp::gen_or_load;

use nexus_network::*;
use workers::*;
use post::*;

const INDEX: &[u8] = include_bytes!("../../../res/index.html");
const CSS: &[u8] = include_bytes!("../../../res/style.css");
const JS: &[u8] = include_bytes!("../../../res/nexus.js");

fn get_stats(_state: WorkerState) -> Result<Response<Body>> {
    let stats = 77;
    let res = match serde_json::to_string(&stats) {
        Ok(json) => Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("interal server error".into())
            .unwrap(),
    };
    Ok(res)
}

fn r404() -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("not found".into())?)
}

async fn router(state: WorkerState, req: Request<Body>) -> Result<Response<Body>> {
    //println!("{:?}", req);

    if let Some(proto) = req.headers().get(UPGRADE) {
        let proto = proto.to_str()?;
        match (proto, req.uri().path()) {
            ("nexus", "/msm") => return bin::upgrade(state, req, msm_server_proxy),
            ("nexus", "/pcd") => return bin::upgrade(state, req, pcd_server_proxy),
            //("websocket", "/stats") => return ws::upgrade(state, req, stats),
            _ => return r404(),
        }
    }

    if req.method() == Method::POST {
        match req.uri().path() {
            "/elf" => return post_recv_file(state, req).await,
            "/api" => return post_api(state, req).await,
            _ => return r404(),
        }
    }

    if req.method() != Method::GET {
        return r404();
    }

    match req.uri().path() {
        "/" => Ok(Response::builder()
            .header("Content-Type", "text/html")
            .body(INDEX.into())?),
        "/style.css" => Ok(Response::builder()
            .header("Content-Type", "text/css")
            .body(CSS.into())?),
        "/nexus.js" => Ok(Response::builder()
            .header("Content-Type", "text/javascript")
            .body(JS.into())?),
        "/stats" => get_stats(state),
        _ => r404(),
    }
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
    connect: SocketAddr,

    /// public parameters file
    #[arg(long = "public-params", default_value = "nexus-public.zst")]
    pp_file: String,
}

/* for testing...
use nexus_prover::types::*;
fn empty_pp() -> ParPP {
    use nexus_prover::types::pcd::PublicParams;
    use ark_ff::fields::AdditiveGroup;

    let shape = R1CSShape::<P1> {
        num_constraints: 0,
        num_vars: 0,
        num_io: 0,
        A: Vec::new(),
        B: Vec::new(),
        C: Vec::new(),
    };
    let shape_secondary = R1CSShape::<P2> {
        num_constraints: 0,
        num_vars: 0,
        num_io: 0,
        A: Vec::new(),
        B: Vec::new(),
        C: Vec::new(),
    };

    PublicParams {
        ro_config: ro_config(),
        shape,
        shape_secondary,
        pp: Vec::new(),
        pp_secondary: Vec::new(),
        digest: F1::ZERO,
        _step_circuit: PhantomData,
        _setup_params: PhantomData,
    }
}
*/

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_env_filter("supernova=trace,nexus=trace")
        .init();

    //let subscriber = tracing_subscriber::FmtSubscriber::new();
    //tracing::subscriber::set_global_default(subscriber).unwrap();

    let opts = Opts::parse();

    let pp = gen_or_load(false, 0, &opts.pp_file)?;
    //let pp = empty_pp();
    let state = WorkerState::new(pp);

    start_local_workers(state.clone())?;

    // testing
    //manage_proof(&state, 16)?;

    if opts.msm {
        bin::client(state.clone(), opts.connect, "msm", msm_client_proxy).await?;
    }
    if opts.pcd {
        bin::client(state.clone(), opts.connect, "pcd", pcd_client_proxy).await?;
    }

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

    println!("Listening on http://{}", server.local_addr());
    server.await?;
    Ok(())
}
