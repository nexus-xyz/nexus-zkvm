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
    &components::SUB,
    &components::SLTU,
    &components::SLTIU,
    &components::SLT,
    &components::SLTI,
    &components::SLL,
    &components::SLLI,
    &components::SRL,
    &components::SRLI,
    &components::SRA,
    &components::SRAI,
    &components::LB,
    &components::LH,
    &components::LW,
    &components::LBU,
    &components::LHU,
    &components::SB,
    &components::SH,
    &components::SW,
    &components::AND,
    &components::ANDI,
    &components::OR,
    &components::ORI,
    &components::XOR,
    &components::XORI,
    &components::LUI,
    &components::AUIPC,
    &components::BitwiseMultiplicity,
];

pub use prove::{prove, Proof};
pub use verify::verify;
