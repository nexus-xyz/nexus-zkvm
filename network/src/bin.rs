use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use http::uri;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    Body, Client, Request, Response, StatusCode,
};

use super::pcd::*;
use super::*;

const MAX_SIZE: u32 = 40 * 1024 * 1024;

pub async fn read_msg(upgraded: &mut Upgraded) -> Result<NexusMsg> {
    let size = upgraded.read_u32().await?;
    if size > MAX_SIZE {
        tracing::warn!(
            target: LOG_TARGET,
            max_size = MAX_SIZE,
            "Read size {size} exceeded the limit",
        );
        return Err("bad size".into());
    }
    let mut b = vec![0; size as usize];
    upgraded.read_exact(&mut b).await?;
    let t = decode_lz4(&b)?;
    Ok(t)
}

pub async fn write_msg(upgraded: &mut Upgraded, msg: &NexusMsg) -> Result<()> {
    let v = encode_lz4(msg)?;
    let size = v.len() as u32;
    if size > MAX_SIZE {
        tracing::warn!(
            target: LOG_TARGET,
            max_size = MAX_SIZE,
            "Write size {size} exceeded the limit",
        );
        return Err("bad size".into());
    }
    upgraded.write_u32(size).await?;
    upgraded.write_all(&v).await?;
    Ok(())
}

pub fn upgrade<S, F>(
    state: S,
    req: Request<Body>,
    f: fn(S, Upgraded) -> F,
) -> Result<Response<Body>>
where
    S: Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
{
    let proto = req.headers().get(UPGRADE);
    let proto = proto.ok_or::<DynError>("bad header".into())?;
    let proto = proto.clone();

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    "new node connected, switching protocols",
                );
                if let Err(e) = f(state, upgraded).await {
                    tracing::warn!(
                        target: LOG_TARGET,
                        error = ?e,
                    );
                };
            }
            Err(e) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    error = ?e,
                    "failed to switch protocols",
                );
            }
        }
    });

    let res = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "upgrade")
        .header(UPGRADE, proto)
        .body(Body::empty())?;
    Ok(res)
}

pub async fn client<S, F>(
    state: S,
    addr: &uri::Authority,
    path: &str,
    f: fn(S, Upgraded) -> F,
) -> Result<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    let req = Request::builder()
        .uri(format!("http://{}/{}", addr, path))
        .header(UPGRADE, "nexus")
        .body(Body::empty())?;

    let res = Client::new().request(req).await?;
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err("server refused upgrade".into());
    }

    let upgraded = hyper::upgrade::on(res).await?;
    tracing::debug!(
        target: LOG_TARGET,
        "connected to {addr}",
    );
    f(state, upgraded).await
}
