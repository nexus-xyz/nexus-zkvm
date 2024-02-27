pub mod api;
pub mod bin;
pub mod client;
pub mod pcd;
pub mod ws;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = DynError> = std::result::Result<T, E>;

pub const LOG_TARGET: &str = "nexus-network";
