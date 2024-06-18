use std::{net::SocketAddr, path::PathBuf};

use super::Config;

#[derive(Debug, serde_wrapper::Deserialize)]
pub struct RpcConfig {
    pub bind_addr: SocketAddr,
    pub db_path: PathBuf,
}

impl Config for RpcConfig {
    const PREFIX: &'static str = "NETWORK_RPC";
}

impl Default for RpcConfig {
    fn default() -> Self {
        // returns local dev config
        Self {
            bind_addr: "127.0.0.1:8080".parse().expect("bind addr is valid"),
            db_path: "/tmp/nexus-rpc-rocksdb".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config() {
        std::env::set_var("NEXUS_NETWORK_RPC_BINDADDR", "127.0.0.1:8080");
        std::env::set_var("NEXUS_NETWORK_RPC_DBPATH", "/tmp/db");

        let config = <RpcConfig as Config>::from_env().unwrap();

        assert_eq!(config.bind_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.db_path.to_str(), Some("/tmp/db"));
    }
}
