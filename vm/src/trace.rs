use serde::{Deserialize, Serialize};

use crate::cpu::{instructions::InstructionResult, RegisterFile};
use crate::elf::ElfFile;
use crate::emulator::{Emulator, LinearEmulator, LinearMemoryLayout};
use crate::error::{Result, VMError};
use crate::memory::MemoryRecords;
use crate::riscv::{Instruction, Opcode};

/// A program step.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Timestamp of the step.
    pub timestamp: u32,
    /// Value of program counter for instruction.
    pub pc: u32,
    /// Value of program counter after instruction.
    pub next_pc: u32,
    /// Encoded instruction.
    pub op: Opcode,
    /// Result of instruction evaluation.
    pub result: InstructionResult,
    /// Memory records for instruction evaluation.
    pub memory_records: MemoryRecords,
}

/// A sequence of program steps.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Starting register file for this block.
    pub regs: RegisterFile,
    /// Sequence of `k` or basic-block sized steps contained in this block.
    pub steps: Vec<Step>,
}

pub trait Trace {
    fn get_blocks_iter(&self) -> impl Iterator<Item = &Block> + '_;

    fn get_start(&self) -> usize;

    /// Return block with index `n`, if it is contained in this (sub)trace.
    fn block(&self, n: usize) -> Option<&Block> {
        self.get_blocks_iter().nth(n - self.get_start())
    }
}

/// Represents a program trace over uniform blocks.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct UniformTrace {
    /// Steps per block.
    pub k: usize,
    /// First block in this (sub)trace.
    pub start: usize,
    /// The blocks contained in this trace.
    pub blocks: Vec<Block>,
}

impl Trace for UniformTrace {
    fn get_blocks_iter(&self) -> impl Iterator<Item = &Block> + '_ {
        self.blocks.iter()
    }

    fn get_start(&self) -> usize {
        self.start
    }
}

impl UniformTrace {
    /// Create a subtrace containing only block `n`.
    pub fn get(&self, n: usize) -> Option<Self> {
        Some(UniformTrace {
            k: self.k,
            start: n,
            blocks: vec![self.block(n)?.clone()],
        })
    }

    /// Split a trace into subtraces with `n` blocks each. Note, the
    /// final subtrace may contain fewer than `n` blocks.
    pub fn split_by(&self, n: usize) -> impl Iterator<Item = Self> + '_ {
        let mut index = 0;
        self.blocks.chunks(n).map(move |bs| {
            let start = index;
            index += n;
            UniformTrace {
                k: self.k,
                start,
                blocks: bs.to_vec(),
            }
        })
    }

    /// Estimate the size, in bytes, of this trace.
    pub fn estimate_size(&self) -> usize {
        use std::mem::size_of_val as sizeof;
        sizeof(self)
            + self.blocks.len()
                * (sizeof(&self.blocks[0])
                    + self.blocks[0].steps.len() * sizeof(&self.blocks[0].steps[0]))
    }
}

/// Represents a program trace over basic blocks.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct BBTrace {
    /// First block in this (sub)trace.
    pub start: usize,
    /// The blocks contained in this trace.
    pub blocks: Vec<Block>,
}

impl Trace for BBTrace {
    fn get_blocks_iter(&self) -> impl Iterator<Item = &Block> + '_ {
        self.blocks.iter()
    }

    fn get_start(&self) -> usize {
        self.start
    }
}

impl BBTrace {
    /// Create a subtrace containing only block `n`.
    pub fn get(&self, n: usize) -> Option<Self> {
        Some(BBTrace {
            start: n,
            blocks: vec![self.block(n)?.clone()],
        })
    }

    /// Split a trace into subtraces with `n` blocks each. Note, the
    /// final subtrace may contain fewer than `n` blocks.
    pub fn split_by(&self, n: usize) -> impl Iterator<Item = Self> + '_ {
        self.blocks.chunks(n).enumerate().map(move |(i, bs)| Self {
            start: i * n,
            blocks: bs.to_vec(),
        })
    }
}

// Generate a `Step` by evaluating the next instruction of `vm`.
fn step(
    vm: &mut LinearEmulator,
    bare_instruction: &Instruction,
    pc: u32,
    timestamp: u32,
) -> Result<Step> {
    let (result, memory_records) = vm.execute_instruction(bare_instruction)?;

    let next_pc = vm.executor.cpu.pc.value;

    let step = Step {
        timestamp,
        pc,
        next_pc,
        op: bare_instruction.opcode.clone(),
        result,
        memory_records,
    };

    Ok(step)
}

// Generate a `Block` by evaluating `k` steps of `vm`.
fn k_step(vm: &mut LinearEmulator, k: usize) -> (Option<Block>, Result<()>) {
    let mut block = Block {
        regs: vm.executor.cpu.registers,
        steps: Vec::new(),
    };

    for _ in 0..k {
        match vm.fetch_block(vm.get_executor().cpu.pc.value) {
            Err(e) => return (None, Err(e)),
            Ok(basic_block) => {
                for instruction in basic_block.0.iter() {
                    if block.steps.len() == k {
                        return (Some(block), Ok(()));
                    }

                    let pc = vm.executor.cpu.pc.value;
                    let timestamp = vm.executor.global_clock as u32;

                    match step(vm, instruction, pc, timestamp) {
                        Ok(step) => block.steps.push(step),
                        Err(VMError::VMExited(n)) => {
                            block.steps.push(Step {
                                timestamp,
                                pc,
                                next_pc: pc,
                                op: instruction.opcode.clone(),
                                result: Some(n),
                                memory_records: MemoryRecords::default(),
                            });

                            return (Some(block), Err(VMError::VMExited(n)));
                        }
                        Err(e) => return (None, Err(e)),
                    }
                }
            }
        }
    }

    (Some(block), Ok(()))
}

/// Trace a program for a given `k`.
pub fn k_trace(
    elf: ElfFile,
    ad_hash: &[u32],
    public_input: &[u32],
    private_input: &[u8],
    k: usize,
) -> Result<UniformTrace> {
    assert!(k > 0);

    // todo: get memory segment using a first-pass trace
    let mut vm = LinearEmulator::from_elf(
        LinearMemoryLayout::default(),
        ad_hash,
        elf,
        public_input,
        private_input,
    );

    let mut trace = UniformTrace {
        k,
        start: 0,
        blocks: Vec::new(),
    };

    loop {
        match k_step(&mut vm, k) {
            (Some(block), Ok(())) => trace.blocks.push(block),
            (Some(block), Err(e)) => {
                if !block.steps.is_empty() {
                    trace.blocks.push(block);
                }

                match e {
                    VMError::VMExited(0) => return Ok(trace),
                    _ => return Err(e),
                }
            }
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}

// Generate a `Block` by evaluating a basic block in the `vm`.
fn bb_step(vm: &mut LinearEmulator) -> (Option<Block>, Result<()>) {
    let mut block = Block {
        regs: vm.executor.cpu.registers,
        steps: Vec::new(),
    };

    match vm.fetch_block(vm.get_executor().cpu.pc.value) {
        Err(e) => return (None, Err(e)),
        Ok(basic_block) => {
            for instruction in basic_block.0.iter() {
                let pc = vm.executor.cpu.pc.value;
                let timestamp = vm.executor.global_clock as u32;

                match step(vm, instruction, pc, timestamp) {
                    Ok(step) => block.steps.push(step),
                    Err(VMError::VMExited(n)) => {
                        block.steps.push(Step {
                            timestamp,
                            pc,
                            next_pc: pc,
                            op: instruction.opcode.clone(),
                            result: Some(n),
                            memory_records: MemoryRecords::default(),
                        });

                        return (Some(block), Err(VMError::VMExited(n)));
                    }
                    Err(e) => return (None, Err(e)),
                }
            }
        }
    }

    (Some(block), Ok(()))
}

/// Trace a program over basic blocks.
pub fn bb_trace(
    elf: ElfFile,
    ad_hash: &[u32],
    public_input: &[u32],
    private_input: &[u8],
) -> Result<BBTrace> {
    // todo: get memory segment using a first-pass trace
    let mut vm = LinearEmulator::from_elf(
        LinearMemoryLayout::default(),
        ad_hash,
        elf,
        public_input,
        private_input,
    );

    let mut trace = BBTrace {
        start: 0,
        blocks: Vec::new(),
    };

    loop {
        match bb_step(&mut vm) {
            (Some(block), Ok(())) => trace.blocks.push(block),
            (Some(block), Err(e)) => {
                if !block.steps.is_empty() {
                    trace.blocks.push(block);
                }

                match e {
                    VMError::VMExited(0) => return Ok(trace),
                    _ => return Err(e),
                }
            }
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemAccessSize, MemoryRecord};
    use crate::riscv::{BuiltinOpcode, Register};

    #[test]
    fn test_k1_trace_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let trace = k_trace(elf_file, &[], &[], &[], 1).unwrap();

        // check the first block
        let block = trace.block(0).unwrap();

        assert_eq!(block.steps.len(), 1);
        assert_eq!(trace.block(1).unwrap().regs[Register::X3], 9449480); // check global pointer is updated

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 1);
        assert_eq!(step.pc, 9445384);
        assert_eq!(step.next_pc, 9445388);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(9449480));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(12).unwrap();

        assert_eq!(block.steps.len(), 1);
        assert_eq!(trace.block(13).unwrap().regs, block.regs); // sw leaves registers unchanged

        let mut step = block.steps[0].clone();

        assert_eq!(step.timestamp, 13);
        assert_eq!(step.pc, 9445444);
        assert_eq!(step.next_pc, 9445448);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::SW));
        assert_eq!(step.result, None);
        assert_eq!(step.memory_records.len(), 1);

        assert!(step
            .memory_records
            .take(&MemoryRecord::StoreRecord(
                (MemAccessSize::Word, 9445368, 9445416, 0),
                13,
                0
            ))
            .is_some());

        let block = trace.block(trace.blocks.len() - 1).unwrap();

        assert_eq!(block.steps.len(), 1);

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, trace.blocks.len() as u32);
        assert_eq!(step.pc, 9445476);
        assert_eq!(step.next_pc, 9445476);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }

    #[test]
    fn test_k8_trace_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let trace = k_trace(elf_file, &[], &[], &[], 8).unwrap();

        // check the first block
        let block = trace.block(0).unwrap();

        assert_eq!(block.steps.len(), 8);
        assert_eq!(trace.block(1).unwrap().regs[Register::X3], 9448408); // check global pointer is updated (also after `addi gp, gp, -1072` at timestamp 2)

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 1);
        assert_eq!(step.pc, 9445384);
        assert_eq!(step.next_pc, 9445388);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(9449480));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(1).unwrap();

        assert_eq!(block.steps.len(), 8);

        let mut step = block.steps[4].clone();

        assert_eq!(step.timestamp, 13);
        assert_eq!(step.pc, 9445444);
        assert_eq!(step.next_pc, 9445448);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::SW));
        assert_eq!(step.result, None);
        assert_eq!(step.memory_records.len(), 1);

        assert!(step
            .memory_records
            .take(&MemoryRecord::StoreRecord(
                (MemAccessSize::Word, 9445368, 9445416, 0),
                13,
                0
            ))
            .is_some());

        // check last block, todo: update to use ecall exit
        let block = trace.block(trace.blocks.len() - 1).unwrap();

        assert!(block.steps.len() <= 8);

        let step = block.steps.last().unwrap().clone();

        assert_eq!(
            step.timestamp,
            (8 * (trace.blocks.len() as u32 - 1) + block.steps.len() as u32)
        );
        assert_eq!(step.pc, 9445476);
        assert_eq!(step.next_pc, 9445476);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }

    #[test]
    fn test_bb_trace_nexus_rt_binary() {
        let elf_file = ElfFile::from_path("test/fib_10.elf").expect("Unable to load ELF file");
        let trace = bb_trace(elf_file, &[], &[], &[]).unwrap();

        // check the first block
        let block = trace.block(0).unwrap();

        assert_eq!(trace.block(1).unwrap().regs[Register::X3], 9448408); // check global pointer is updated (also after `addi gp, gp, -1072` at timestamp 2)

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 1);
        assert_eq!(step.pc, 9445384);
        assert_eq!(step.next_pc, 9445388);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(9449480));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(4).unwrap();

        let mut step = block.steps[1].clone();

        assert_eq!(step.timestamp, 13);
        assert_eq!(step.pc, 9445444);
        assert_eq!(step.next_pc, 9445448);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::SW));
        assert_eq!(step.result, None);
        assert_eq!(step.memory_records.len(), 1);

        assert!(step
            .memory_records
            .take(&MemoryRecord::StoreRecord(
                (MemAccessSize::Word, 9445368, 9445416, 0),
                13,
                0
            ))
            .is_some());

        // check last block, todo: update to use ecall exit
        let block = trace.block(trace.blocks.len() - 1).unwrap();

        assert!(block.steps.len() <= 8);

        let step = block.steps.last().unwrap().clone();

        assert_eq!(step.pc, 9445476);
        assert_eq!(step.next_pc, 9445476);
        assert_eq!(step.op, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }
}
