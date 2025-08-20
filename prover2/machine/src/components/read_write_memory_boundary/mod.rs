#![allow(clippy::enum_variant_names)]

mod private_memory;
mod pub_input_output_memory;
mod static_memory;

pub use private_memory::PrivateMemoryBoundary;
pub use pub_input_output_memory::PubMemoryBoundary;
pub use static_memory::StaticMemoryBoundary;
