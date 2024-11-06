use serde::{Deserialize, Serialize};

use crate::{
    cpu::{instructions::InstructionResult, RegisterFile},
    elf::ElfFile,
    emulator::{Emulator, LinearEmulator, LinearMemoryLayout},
    error::{Result, VMError},
    memory::MemoryRecords,
    riscv::{BasicBlock, Instruction},
};

/// A program step.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Timestamp of the step.
    pub timestamp: u32,
    /// Value of program counter for instruction.
    pub pc: u32,
    /// Value of program counter after instruction.
    pub next_pc: u32,
    /// Raw instruction.
    pub raw_instruction: u32,
    /// Encoded instruction.
    pub instruction: Instruction,
    /// Result of instruction evaluation.
    pub result: InstructionResult,
    /// Memory records for instruction evaluation.
    pub memory_records: MemoryRecords,
}

/// A sequence of program steps.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Starting register file for this block.
    pub regs: RegisterFile,
    /// Sequence of `k` or basic-block sized steps contained in this block.
    pub steps: Vec<Step>,
}

pub trait Trace {
    fn get_memory_layout(&self) -> &LinearMemoryLayout;

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
    /// Memory layout.
    pub memory_layout: LinearMemoryLayout,
    /// Steps per block.
    pub k: usize,
    /// First block in this (sub)trace.
    pub start: usize,
    /// The blocks contained in this trace.
    pub blocks: Vec<Block>,
}

impl Trace for UniformTrace {
    fn get_memory_layout(&self) -> &LinearMemoryLayout {
        &self.memory_layout
    }

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
            memory_layout: self.memory_layout,
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
                memory_layout: self.memory_layout,
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
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BBTrace {
    /// Memory layout.
    pub memory_layout: LinearMemoryLayout,
    /// First block in this (sub)trace.
    pub start: usize,
    /// The blocks contained in this trace.
    pub blocks: Vec<Block>,
}

impl Trace for BBTrace {
    fn get_memory_layout(&self) -> &LinearMemoryLayout {
        &self.memory_layout
    }

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
            memory_layout: self.memory_layout,
            start: n,
            blocks: vec![self.block(n)?.clone()],
        })
    }

    /// Split a trace into subtraces with `n` blocks each. Note, the
    /// final subtrace may contain fewer than `n` blocks.
    pub fn split_by(&self, n: usize) -> impl Iterator<Item = Self> + '_ {
        self.blocks.chunks(n).enumerate().map(move |(i, bs)| Self {
            memory_layout: self.memory_layout,
            start: i * n,
            blocks: bs.to_vec(),
        })
    }
}

// Generate a `Step` by evaluating the next instruction of `vm`.
fn step(
    vm: &mut LinearEmulator,
    instruction: &Instruction,
    pc: u32,
    timestamp: u32,
) -> Result<Step> {
    let (result, memory_records) = vm.execute_instruction(instruction)?;

    let next_pc = vm.executor.cpu.pc.value;

    let step = Step {
        timestamp,
        pc,
        next_pc,
        raw_instruction: instruction.encode(),
        instruction: instruction.clone(),
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
                                raw_instruction: instruction.encode(),
                                instruction: instruction.clone(),
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
        memory_layout: vm.memory_layout,
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
                            raw_instruction: instruction.encode(),
                            instruction: instruction.clone(),
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
        memory_layout: vm.memory_layout,
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

/// Trace a program over basic blocks.
pub fn bb_trace_direct(basic_blocks: &Vec<BasicBlock>) -> Result<BBTrace> {
    let mut vm = LinearEmulator::from_basic_blocks(LinearMemoryLayout::default(), basic_blocks);

    let mut trace = BBTrace {
        memory_layout: vm.memory_layout,
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
            (None, Err(VMError::VMOutOfInstructions)) => return Ok(trace),
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemAccessSize, MemoryRecord};
    use crate::riscv::{BuiltinOpcode, Opcode, Register};
    use nexus_common::riscv::instruction::InstructionType;

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
        assert_eq!(step.raw_instruction, 0x00001197);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
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
        assert_eq!(step.raw_instruction, 0x00112E23);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::SW));
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
        assert_eq!(step.raw_instruction, 0x00000073);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ECALL));
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
        assert_eq!(step.raw_instruction, 0x00001197);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(9449480));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(1).unwrap();

        assert_eq!(block.steps.len(), 8);

        let mut step = block.steps[4].clone();

        assert_eq!(step.timestamp, 13);
        assert_eq!(step.pc, 9445444);
        assert_eq!(step.next_pc, 9445448);
        assert_eq!(step.raw_instruction, 0x00112E23);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::SW));
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

        assert!(block.steps.len() <= 8);

        let step = block.steps.last().unwrap().clone();

        assert_eq!(
            step.timestamp,
            (8 * (trace.blocks.len() as u32 - 1) + block.steps.len() as u32)
        );
        assert_eq!(step.pc, 9445476);
        assert_eq!(step.next_pc, 9445476);
        assert_eq!(step.raw_instruction, 0x00000073);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ECALL));
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
        assert_eq!(step.raw_instruction, 0x00001197);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(9449480));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(4).unwrap();

        let mut step = block.steps[1].clone();

        assert_eq!(step.timestamp, 13);
        assert_eq!(step.pc, 9445444);
        assert_eq!(step.next_pc, 9445448);
        assert_eq!(step.raw_instruction, 0x00112E23);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::SW));
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

        assert!(block.steps.len() <= 8);

        let step = block.steps.last().unwrap().clone();

        assert_eq!(step.pc, 9445476);
        assert_eq!(step.next_pc, 9445476);
        assert_eq!(step.raw_instruction, 0x00000073);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }

    #[rustfmt::skip]
    fn setup_basic_block_ir() -> Vec<BasicBlock>
    {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1, InstructionType::IType),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_bb_trace_simple_from_basic_block_ir() {
        let basic_blocks = setup_basic_block_ir();
        let trace = bb_trace_direct(&basic_blocks).expect("Failed to create trace");

        let first_step = trace.blocks[0].steps.first().expect("No steps in trace");
        assert_eq!(first_step.result, Some(1), "Unexpected Fibonacci result",);

        let last_step = trace.blocks[0].steps.last().expect("No steps in trace");
        // The result of 30th Fibonacci number is 1346269
        assert_eq!(
            last_step.result,
            Some(1346269),
            "Unexpected Fibonacci result"
        );
    }
}
