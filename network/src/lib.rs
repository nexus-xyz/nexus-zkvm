pub mod api;
pub mod bin;
pub mod client;
pub mod pcd;
pub mod ws;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, DynError>;

pub const LOG_TARGET: &str = "nexus-network";
