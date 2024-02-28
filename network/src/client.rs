use std::path::Path;

use http::uri;
use hyper::body::{Buf, HttpBody};
use hyper::client::HttpConnector;
use tokio::runtime;

use nexus_prover::Proof;

use crate::client::NexusAPI::{Error, NexusProof, Program, Query};
use crate::{api::NexusAPI, Result};

pub const LOG_TARGET: &str = "nexus-network::client";

// const URL: &str = "http://35.209.216.211:80/api";

#[derive(Clone)]
pub struct Client {
    url: uri::Authority,
    client: hyper::Client<HttpConnector>,
}

impl Client {
    pub fn new<U: TryInto<uri::Authority>>(url: U) -> Result<Self> {
        let url = url.try_into().map_err(|_err| "invalid url".to_owned())?;
        let client = hyper::Client::new();

        Ok(Self { url, client })
    }

    async fn nexus_api(&self, msg: &NexusAPI) -> Result<NexusAPI> {
        let url = format!("http://{}/api", self.url);
        let req = hyper::Request::post(&url).body(serde_json::to_string(msg)?.into())?;
        let response = self.client.request(req).await?;

        let body = response.collect().await?.aggregate();
        let msg = serde_json::from_reader(body.reader())?;

        Ok(msg)
    }

    fn request(&self, msg: NexusAPI) -> Result<Proof> {
        tracing::info!(
            target: LOG_TARGET,
            "sending request to {}",
            self.url,
        );

        let client = self.clone();
        let response = std::thread::spawn(move || -> Result<NexusAPI> {
            let rt = runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            rt.block_on(client.nexus_api(&msg))
        })
        .join()
        .map_err(|_err| "request failed".to_owned())??;

        match response {
            NexusProof(p) => Ok(p),
            Error(m) => Err(m.into()),
            _ => Err("unexpected response".into()),
        }
    }

    pub fn submit_proof(&self, account: String, path: &Path) -> Result<Proof> {
        let bytes = std::fs::read(path)?;
        let msg = Program { account, elf: bytes };
        self.request(msg)
    }

    pub fn fetch_proof(&self, hash: &str) -> Result<Proof> {
        let msg = Query { hash: hash.to_string() };
        self.request(msg)
    }
}
