mod components;
mod framework;
mod lookups;
mod side_note;

mod prove;
mod verify;

const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &components::Cpu,
    &components::CpuBoundary,
    &components::RegisterMemory,
    &components::RegisterMemoryBoundary,
    &components::ADD,
    &components::ADDI,
];

pub use prove::{prove, Proof};
pub use verify::verify;
