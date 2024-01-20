pub mod bin;
pub mod ws;
pub mod pcd;
pub mod api;
pub mod client;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = DynError> = std::result::Result<T, E>;
