//! Translation layer for using NexusVM with Jolt (https://github.com/a16z/jolt).
//!
//! JoltVM works with a superset of NexusVM instruction set, hence the mapping is almost identical.
//! Mainly, it's required to modify the link script for the memory shift, fetch additional sections
//! from the ELF file, and build a trace of memory accesses.

#![allow(clippy::type_complexity)]

use jolt_common::{constants::MEMORY_OPS_PER_INSTRUCTION, rv_trace as jolt_rv};
use jolt_core::{
    jolt::vm::{
        bytecode::BytecodeRow as JoltBytecodeRow,
        rv32i_vm::{self, RV32ISubtables, C, M, RV32I},
        Jolt,
    },
    poly::{commitment::hyrax::HyraxScheme, field::JoltField},
    utils::thread::unsafe_allocate_zero_vec,
};

use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

const LOG_TARGET: &str = "nexus-jolt";

pub type F = ark_bn254::Fr;
pub type PCS = HyraxScheme<ark_bn254::G1Projective>;
pub type JoltPreprocessing = jolt_core::jolt::vm::JoltPreprocessing<F, PCS>;
pub type JoltProof = jolt_core::jolt::vm::JoltProof<C, M, F, PCS, RV32I, RV32ISubtables<F>>;
pub type JoltCommitments = jolt_core::jolt::vm::JoltCommitments<PCS>;

mod convert;
mod error;

pub mod parse;
pub mod trace;

pub use error::Error;

/// Wrapper for initialized VM.
pub struct VM {
    /// Initialized Nexus VM.
    vm: nexus_riscv::eval::VM,

    /// Instructions section.
    insts: Vec<jolt_rv::ELFInstruction>,

    /// Flattened initial state of memory.
    mem_init: Vec<(u64, u8)>,
}

impl VM {
    pub fn bytecode_size(&self) -> usize {
        self.insts.len()
    }
}

pub fn preprocess(vm: &VM) -> JoltPreprocessing {
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
    trace: Vec<jolt_rv::RVTraceRow>,
    preprocessing: &JoltPreprocessing,
) -> Result<(JoltProof, JoltCommitments), Error> {
    let (io_device, bytecode_trace, instruction_trace, memory_trace, circuit_flags) =
        build_jolt_trace::<F>(&trace);

    Ok(rv32i_vm::RV32IJoltVM::prove(
        io_device,
        bytecode_trace,
        memory_trace,
        instruction_trace,
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

fn build_jolt_trace<F: JoltField>(
    trace: &[jolt_rv::RVTraceRow],
) -> (
    jolt_rv::JoltDevice,
    Vec<JoltBytecodeRow>,
    Vec<Option<rv32i_vm::RV32I>>,
    Vec<[jolt_rv::MemoryOp; MEMORY_OPS_PER_INSTRUCTION]>,
    Vec<F>,
) {
    // Nexus VM doesn't use JoltVM provided IO.
    const MAX_INPUT_SIZE: u64 = 0;
    const MAX_OUTPUT_SIZE: u64 = 0;

    let io_device = jolt_rv::JoltDevice::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);

    // copy of [`jolt_core::host::Program::trace`]
    let bytecode_trace: Vec<JoltBytecodeRow> = trace
        .par_iter()
        .map(|row| JoltBytecodeRow::from_instruction::<rv32i_vm::RV32I>(&row.instruction))
        .collect();

    let instruction_trace: Vec<Option<rv32i_vm::RV32I>> = trace
        .par_iter()
        .map(|row| {
            if let Ok(jolt_instruction) = rv32i_vm::RV32I::try_from(row) {
                Some(jolt_instruction)
            } else {
                // Instruction does not use lookups
                None
            }
        })
        .collect();

    let memory_trace: Vec<[jolt_rv::MemoryOp; MEMORY_OPS_PER_INSTRUCTION]> =
        trace.iter().map(|row| row.into()).collect();

    let padded_trace_len = trace.len().next_power_of_two();
    let mut circuit_flag_trace =
        unsafe_allocate_zero_vec(padded_trace_len * jolt_rv::NUM_CIRCUIT_FLAGS);
    circuit_flag_trace
        .par_chunks_mut(padded_trace_len)
        .enumerate()
        .for_each(|(flag_index, chunk)| {
            chunk.iter_mut().zip(trace.iter()).for_each(|(flag, row)| {
                if row.instruction.to_circuit_flags()[flag_index] {
                    *flag = F::one();
                }
            });
        });

    (
        io_device,
        bytecode_trace,
        instruction_trace,
        memory_trace,
        circuit_flag_trace,
    )
}
