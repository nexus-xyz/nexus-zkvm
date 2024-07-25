#[cfg(not(feature = "jolt-io"))]
mod base;
#[cfg(not(feature = "jolt-io"))]
pub use base::setup;

#[cfg(feature = "jolt-io")]
mod jolt;
#[cfg(feature = "jolt-io")]
pub use jolt::setup;
