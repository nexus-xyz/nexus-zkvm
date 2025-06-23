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
    &components::ReadWriteMemory,
    &components::ReadWriteMemoryBoundary,
    &components::ProgramMemory,
    &components::ProgramMemoryBoundary,
    &components::ADD,
    &components::ADDI,
    &components::LB,
    &components::LH,
    &components::LW,
    &components::LBU,
    &components::LHU,
];

pub use prove::{prove, Proof};
pub use verify::verify;
