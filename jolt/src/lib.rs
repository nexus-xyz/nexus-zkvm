//! Translation layer for using NexusVM with Jolt (https://github.com/a16z/jolt).
//!
//! JoltVM works with a superset of NexusVM instruction set, hence the mapping is almost identical.
//! Mainly, it's required to modify the link script for the memory shift, fetch additional sections
//! from the ELF file, and build a trace of memory accesses.

#![allow(clippy::type_complexity)]

pub use jolt_common;
pub use jolt_core;

use jolt_common::rv_trace as jolt_rv;
use jolt_core::{
    jolt::vm::{bytecode::BytecodeRow as JoltBytecodeRow, rv32i_vm::RV32I, JoltTraceStep},
    poly::field::JoltField,
    utils::thread::unsafe_allocate_zero_vec,
};

use nexus_vm::{eval::NexusVM, memory::Memory};

use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use strum::EnumCount;

const LOG_TARGET: &str = "nexus-jolt";

mod convert;
mod error;

pub mod parse;
pub mod trace;

pub use error::Error;

/// Wrapper for initialized VM.
pub struct VM<M: Memory> {
    /// Initialized Nexus VM.
    pub vm: NexusVM<M>,

    /// Instructions section.
    pub insts: Vec<jolt_rv::ELFInstruction>,

    /// Flattened initial state of memory.
    pub mem_init: Vec<(u64, u8)>,
}

impl<M: Memory> VM<M> {
    pub fn bytecode_size(&self) -> usize {
        self.insts.len()
    }
}

pub fn build_jolt_trace<F: JoltField>(
    raw_trace: &[jolt_rv::RVTraceRow],
) -> (jolt_rv::JoltDevice, Vec<JoltTraceStep<RV32I>>, Vec<F>) {
    // Nexus VM doesn't use JoltVM provided IO.
    const MAX_INPUT_SIZE: u64 = 0;
    const MAX_OUTPUT_SIZE: u64 = 0;

    let io_device = jolt_rv::JoltDevice::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);

    // copy of [`jolt_core::host::Program::trace`]
    let trace: Vec<_> = raw_trace
        .into_par_iter()
        .flat_map(|row| match row.instruction.opcode {
            jolt_rv::RV32IM::MULH
            | jolt_rv::RV32IM::MULHSU
            | jolt_rv::RV32IM::DIV
            | jolt_rv::RV32IM::DIVU
            | jolt_rv::RV32IM::REM
            | jolt_rv::RV32IM::REMU => unimplemented!(),
            _ => vec![row],
        })
        .map(|row| {
            let instruction_lookup = if let Ok(jolt_instruction) = RV32I::try_from(row) {
                Some(jolt_instruction)
            } else {
                // Instruction does not use lookups
                None
            };

            JoltTraceStep {
                instruction_lookup,
                bytecode_row: JoltBytecodeRow::from_instruction::<RV32I>(&row.instruction),
                memory_ops: (row).into(),
            }
        })
        .collect();
    let padded_trace_len = trace.len().next_power_of_two();

    let mut circuit_flag_trace =
        unsafe_allocate_zero_vec(padded_trace_len * jolt_rv::NUM_CIRCUIT_FLAGS);
    circuit_flag_trace
        .par_chunks_mut(padded_trace_len)
        .enumerate()
        .for_each(|(flag_index, chunk)| {
            chunk.iter_mut().zip(trace.iter()).for_each(|(flag, row)| {
                let packed_circuit_flags = row.bytecode_row.bitflags >> RV32I::COUNT;
                // Check if the flag is set in the packed representation
                if (packed_circuit_flags >> (jolt_rv::NUM_CIRCUIT_FLAGS - flag_index - 1)) & 1 != 0
                {
                    *flag = F::one();
                }
            });
        });

    (io_device, trace, circuit_flag_trace)
}
