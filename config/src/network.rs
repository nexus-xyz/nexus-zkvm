use std::net::SocketAddr;

use serde::{Deserialize, Deserializer};

use super::Config;

#[derive(serde_wrapper::Deserialize)]
pub struct NetworkConfig {
    pub api: ApiConfig,
    pub client: ClientConfig,
}

#[derive(serde_wrapper::Deserialize)]
pub struct ApiConfig {
    pub bind_addr: SocketAddr,
}

#[derive(serde_wrapper::Deserialize)]
pub struct ClientConfig {
    #[serde(deserialize_with = "parse_hostname")]
    pub host_name: url::Host,

    #[serde(default)]
    pub port: Option<u16>,
}

impl Config for NetworkConfig {
    const PREFIX: &'static str = "NETWORK";
}

fn parse_hostname<'de, D>(deserializer: D) -> Result<url::Host, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    url::Host::parse(&s).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config() {
        std::env::set_var("NEXUS_NETWORK_API_BINDADDR", "127.0.0.1:8080");
        std::env::set_var("NEXUS_NETWORK_CLIENT_HOSTNAME", "nexus.xyz");

        let config = <NetworkConfig as Config>::from_env().unwrap();
        assert_eq!(
            config.client.host_name,
            url::Host::Domain("nexus.xyz".to_owned())
        );
        assert_eq!(config.client.port, None,);

        std::env::set_var("NEXUS_NETWORK_CLIENT_HOSTNAME", "127.0.0.1");
        std::env::set_var("NEXUS_NETWORK_CLIENT_PORT", "9999");
        let config = <NetworkConfig as Config>::from_env().unwrap();
        assert_eq!(
            config.client.host_name,
            url::Host::<String>::Ipv4("127.0.0.1".parse().unwrap())
        );
        assert_eq!(config.client.port, Some(9999u16),);
    }
}
