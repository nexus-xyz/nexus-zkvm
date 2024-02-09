pub mod bin;
pub mod ws;
pub mod pcd;
pub mod api;
pub mod client;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, DynError>;

pub const LOG_TARGET: &str = "nexus-network";
