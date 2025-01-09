use std::future::Future;
use std::net::SocketAddr;
use hyper::{header::UPGRADE, upgrade::Upgraded, Body, Client, Request, Response, StatusCode};
use fastwebsockets::{
    handshake::generate_key, upgrade, FragmentCollector, Frame, OpCode, Payload, Role, WebSocket,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

type WS = FragmentCollector<Upgraded>;

#[derive(Error, Debug)]
pub enum WebSocketError {
    #[error("WebSocket read error")]
    ReadError(#[from] serde_json::Error),
    #[error("WebSocket write error")]
    WriteError(#[from] serde_json::Error),
    #[error("Failed to upgrade WebSocket connection")]
    UpgradeError(String),
    #[error("Server refused WebSocket upgrade")]
    ServerRefusedUpgrade,
}

pub async fn read_msg<T>(ws: &mut WS) -> Result<T, WebSocketError>
where
    T: for<'a> serde::Deserialize<'a>,
{
    let frame = ws.read_frame().await.map_err(|_| WebSocketError::ReadError(serde_json::Error::custom("Unknown read error")))?;
    match frame.opcode {
        OpCode::Text => serde_json::from_slice(&frame.payload).map_err(WebSocketError::ReadError),
        _ => Err(WebSocketError::ReadError(serde_json::Error::custom("Non-text frame received"))),
    }
}

pub async fn write_msg<T>(ws: &mut WS, msg: &T) -> Result<(), WebSocketError>
where
    T: serde::Serialize,
{
    let v = serde_json::to_vec(msg).map_err(WebSocketError::WriteError)?;
    let payload = Payload::Borrowed(&v);
    let frame = Frame::new(true, OpCode::Text, None, payload);
    ws.write_frame(frame).await.map_err(|_| WebSocketError::WriteError(serde_json::Error::custom("Failed to write frame")))
}

pub fn upgrade<S, F>(state: S, mut req: Request<Body>, f: fn(S, WS) -> F) -> Result<Response<Body>, WebSocketError>
where
    S: Send + 'static,
    F: Future<Output = Result<(), WebSocketError>> + Send + 'static,
{
    let (response, fut) = upgrade::upgrade(&mut req).map_err(|e| WebSocketError::UpgradeError(format!("{:?}", e)))?;

    tokio::task::spawn(async move {
        match fut.await {
            Ok(mut ws) => {
                ws.set_auto_close(true);
                ws.set_auto_pong(true);
                let ws = WS::new(ws);
                if let Err(e) = f(state, ws).await {
                    tracing::warn!(target: LOG_TARGET, error = ?e);
                }
            }
            Err(e) => {
                tracing::warn!(target: LOG_TARGET, error = ?e, "failed to upgrade to ws connection");
            }
        }
    });

    Ok(response)
}

pub async fn client<S, F>(state: S, addr: SocketAddr, f: fn(S, WS) -> F) -> Result<(), WebSocketError>
where
    F: Future<Output = Result<(), WebSocketError>> + Send + 'static,
{
    let req = Request::builder()
        .uri(format!("http://{}/", addr))
        .header(UPGRADE, "websocket")
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .body(Body::empty())
        .map_err(|e| WebSocketError::UpgradeError(format!("Request build failed: {:?}", e)))?;

    let res = Client::new().request(req).await.map_err(|e| WebSocketError::UpgradeError(format!("{:?}", e)))?;
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(WebSocketError::ServerRefusedUpgrade);
    }

    let upgraded = hyper::upgrade::on(res).await.map_err(|e| WebSocketError::UpgradeError(format!("{:?}", e)))?;
    let mut ws = WebSocket::after_handshake(upgraded, Role::Client);
    ws.set_auto_close(true);
    ws.set_auto_pong(true);
    let ws = FragmentCollector::new(ws);

    tokio::spawn(f(state, ws));
    Ok(())
}
