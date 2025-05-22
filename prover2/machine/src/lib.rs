mod components;
mod framework;
mod lookups;
mod side_note;

mod prove;
mod verify;

const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[&components::Cpu, &components::Add];

pub use prove::{prove, Proof};
pub use verify::verify;
