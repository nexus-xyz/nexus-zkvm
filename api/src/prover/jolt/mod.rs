pub mod types;

// re-exports
pub use crate::prover::jolt::types::*;
pub use nexus_jolt::{parse, trace, Error, VM};

use nexus_jolt::{
    build_jolt_trace,
    jolt_common::rv_trace as jolt_rv,
    jolt_core::jolt::vm::{rv32i_vm, Jolt},
};
use nexus_vm::memory::Memory;

pub fn preprocess<M: Memory>(vm: &VM<M>) -> JoltPreprocessing {
    const MAX_BYTECODE_SIZE: usize = 0x400000;
    const MAX_MEMORY_ADDRESS: usize = 1 << 20;
    const MAX_TRACE_LENGTH: usize = 1 << 22;

    rv32i_vm::RV32IJoltVM::preprocess(
        vm.insts.clone(),
        vm.mem_init.clone(),
        MAX_BYTECODE_SIZE,
        MAX_MEMORY_ADDRESS,
        MAX_TRACE_LENGTH,
    )
}

pub fn prove(
    raw_trace: Vec<jolt_rv::RVTraceRow>,
    preprocessing: &JoltPreprocessing,
) -> Result<(JoltProof, JoltCommitments), Error> {
    let (io_device, trace, circuit_flags) = build_jolt_trace::<F>(&raw_trace);

    Ok(rv32i_vm::RV32IJoltVM::prove(
        io_device,
        trace,
        circuit_flags,
        preprocessing.clone(),
    ))
}

pub fn verify(
    preprocessing: JoltPreprocessing,
    proof: JoltProof,
    commitments: JoltCommitments,
) -> Result<(), Error> {
    rv32i_vm::RV32IJoltVM::verify(preprocessing, proof, commitments).map_err(Into::into)
}
