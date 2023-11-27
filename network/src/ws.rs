use std::future::Future;
use std::net::SocketAddr;

use hyper::{header::UPGRADE, upgrade::Upgraded, Body, Client, Request, Response, StatusCode};

use fastwebsockets::{
    handshake::generate_key, upgrade, FragmentCollector, Frame, OpCode, Payload, Role, WebSocket,
};

use super::*;

type WS = FragmentCollector<Upgraded>;

pub async fn read_msg<T>(ws: &mut WS) -> Result<T>
where
    T: for<'a> serde::Deserialize<'a>,
{
    let frame = ws.read_frame().await?;
    match frame.opcode {
        OpCode::Text => Ok(serde_json::from_slice(&frame.payload)?),
        _ => Err("ws read error".into()),
    }
}

pub async fn write_msg<T>(ws: &mut WS, msg: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let v = serde_json::to_vec(msg)?;
    let payload = Payload::Borrowed(&v);
    let frame = Frame::new(true, OpCode::Text, None, payload);
    ws.write_frame(frame).await?;
    Ok(())
}

pub fn upgrade<S, F>(state: S, mut req: Request<Body>, f: fn(S, WS) -> F) -> Result<Response<Body>>
where
    S: Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
{
    let (response, fut) = upgrade::upgrade(&mut req)?;

    tokio::task::spawn(async move {
        match fut.await {
            Ok(mut ws) => {
                ws.set_auto_close(true);
                ws.set_auto_pong(true);
                let ws = WS::new(ws);
                if let Err(e) = f(state, ws).await {
                    eprintln!("Error in websocket connection: {}", e);
                }
            }
            Err(e) => eprintln!("upgrade error: {e}"),
        }
    });

    Ok(response)
}

pub async fn client<S, F>(state: S, addr: SocketAddr, f: fn(S, WS) -> F) -> Result<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    let req = Request::builder()
        .uri(format!("http://{}/", addr))
        .header(UPGRADE, "websocket")
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .body(Body::empty())?;

    let res = Client::new().request(req).await?;
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err("server refused upgrade".into());
    }

    let upgraded = hyper::upgrade::on(res).await?;
    let mut ws = WebSocket::after_handshake(upgraded, Role::Client);
    ws.set_auto_close(true);
    ws.set_auto_pong(true);
    let ws = FragmentCollector::new(ws);

    tokio::spawn(f(state, ws));
    Ok(())
}
