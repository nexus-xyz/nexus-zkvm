use serde::{Deserialize, Serialize};

use crate::{
    cpu::{instructions::InstructionResult, RegisterFile},
    elf::ElfFile,
    emulator::{Emulator, HarvardEmulator, InternalView, LinearEmulator, LinearMemoryLayout, View},
    error::{Result, VMError},
    memory::MemoryRecords,
    riscv::{BasicBlock, Instruction},
    WORD_SIZE,
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

    fn get_num_steps(&self) -> usize {
        self.get_blocks_iter().map(|b| b.steps.len()).sum()
    }

    fn as_blocks_slice(&self) -> &[Block];
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

    fn get_num_steps(&self) -> usize {
        self.k * self.blocks.len()
    }

    fn as_blocks_slice(&self) -> &[Block] {
        self.blocks.as_slice()
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

    fn as_blocks_slice(&self) -> &[Block] {
        self.blocks.as_slice()
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
    vm: &mut impl Emulator,
    instruction: &Instruction,
    pc: u32,
    timestamp: u32,
    force_second_pass: bool,
) -> Result<Step> {
    let (result, memory_records) = vm.execute_instruction(instruction, force_second_pass)?;

    let next_pc = vm.get_executor().cpu.pc.value;

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
fn k_step(
    vm: &mut impl Emulator,
    k: usize,
    force_second_pass: bool,
) -> (Option<Block>, Result<()>) {
    let mut block = Block {
        regs: vm.get_executor().cpu.registers,
        steps: Vec::new(),
    };

    for _ in 0..k {
        match vm.fetch_block(vm.get_executor().cpu.pc.value) {
            Err(e) => {
                // When the block is not fully filled with 'k' instructions,
                // we still return the block we have,
                // along with padded UNIMPL instructions to complete the block.
                // The padded instructions are not executed in the VM.
                if k > 1 && block.steps.len() < k {
                    let last_step = block.steps.last().unwrap();
                    let unimpl_instruction = Instruction::unimpl();
                    let mut padding_steps = Vec::new();

                    for _ in block.steps.len()..k {
                        // 1. Increment the global_clock for each padding step.
                        vm.get_executor_mut().global_clock += 1;

                        // 2. Repeat the last state, but with the global_clock incremented.
                        padding_steps.push(Step {
                            timestamp: vm.get_executor().global_clock as u32,
                            pc: last_step.next_pc,
                            next_pc: last_step.next_pc,
                            raw_instruction: unimpl_instruction.encode(),
                            instruction: unimpl_instruction.clone(),
                            result: None,
                            memory_records: MemoryRecords::default(),
                        });
                    }
                    // 3. Complete the block with UNIMPL instructions
                    block.steps.extend(padding_steps);
                }

                return (Some(block), Err(e));
            }
            Ok(basic_block_entry) => {
                let at = (vm.get_executor().cpu.pc.value as usize
                    - basic_block_entry.start as usize)
                    / WORD_SIZE;

                for instruction in basic_block_entry.block.0[at..].iter() {
                    if block.steps.len() == k {
                        return (Some(block), Ok(()));
                    }

                    let pc = vm.get_executor().cpu.pc.value;
                    let timestamp = vm.get_executor().global_clock as u32;

                    match step(vm, instruction, pc, timestamp, force_second_pass) {
                        Ok(step) => block.steps.push(step),
                        Err(VMError::VMExited(n)) => {
                            block.steps.push(Step {
                                timestamp,
                                pc,
                                next_pc: pc,
                                raw_instruction: instruction.encode(),
                                instruction: instruction.clone(),
                                result: if force_second_pass { None } else { Some(n) },
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

/// Trace a program over an ELF for a given `k`.
///
/// This function generates a trace of the program execution using the provided ELF file.
/// It creates a `UniformTrace` where each block contains `k` steps.
///
/// # Note
///
/// If a block in the trace is smaller than `k`,
/// the block will be padded with UNIMPL instruction to reach the size of `k`.
/// These padded instructions are not executed in the VM.
pub fn k_trace(
    elf: ElfFile,
    ad: &[u8],
    public_input: &[u8],
    private_input: &[u8],
    k: usize,
) -> Result<(View, UniformTrace)> {
    assert!(k > 0);
    let mut harvard = HarvardEmulator::from_elf(&elf, public_input, private_input);
    harvard.get_executor_mut().capture_logs(true);

    match harvard.execute(false) {
        Err(VMError::VMExited(_)) => {
            // todo: consistency check i/o between harvard and linear?
            let mut linear = LinearEmulator::from_harvard(&harvard, elf, ad, private_input)?;

            let mut trace = UniformTrace {
                memory_layout: linear.memory_layout,
                k,
                start: 0,
                blocks: Vec::new(),
            };

            loop {
                match k_step(&mut linear, k, false) {
                    (Some(block), Ok(())) => trace.blocks.push(block),
                    (Some(block), Err(e)) => {
                        if !block.steps.is_empty() {
                            trace.blocks.push(block);
                        }

                        match e {
                            VMError::VMExited(_) => {
                                let mut view = linear.finalize();
                                view.add_logs(&harvard);
                                return Ok((view, trace));
                            }
                            _ => return Err(e),
                        }
                    }
                    (None, Err(e)) => return Err(e),
                    (None, Ok(())) => unreachable!(),
                }
            }
        }
        Err(e) => Err(e),
        Ok(_) => unreachable!(),
    }
}

/// Similar to `k_trace`, but uses HarvardEmulator and supports Intermediate Representation (IR) as input instead of an ELF file.
pub fn k_trace_direct(basic_blocks: &Vec<BasicBlock>, k: usize) -> Result<(View, UniformTrace)> {
    let mut harvard = HarvardEmulator::from_basic_blocks(basic_blocks);

    let mut trace = UniformTrace {
        memory_layout: LinearMemoryLayout::default(), // dummy
        k,
        start: 0,
        blocks: Vec::new(),
    };

    loop {
        match k_step(&mut harvard, k, true) {
            (Some(block), Ok(())) => trace.blocks.push(block),
            (Some(block), Err(e)) => {
                if !block.steps.is_empty() {
                    trace.blocks.push(block);
                }

                match e {
                    VMError::VMExited(_) | VMError::VMOutOfInstructions => {
                        return Ok((harvard.finalize(), trace))
                    }
                    _ => return Err(e),
                }
            }
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}

/// Generate a `Block` by evaluating a basic block in the `vm`.
fn bb_step(vm: &mut impl Emulator) -> (Option<Block>, Result<()>) {
    let mut block = Block {
        regs: vm.get_executor().cpu.registers,
        steps: Vec::new(),
    };

    match vm.fetch_block(vm.get_executor().cpu.pc.value) {
        Err(e) => return (None, Err(e)),
        Ok(basic_block_entry) => {
            let at = (vm.get_executor().cpu.pc.value as usize - basic_block_entry.start as usize)
                / WORD_SIZE;

            for instruction in basic_block_entry.block.0[at..].iter() {
                let pc = vm.get_executor().cpu.pc.value;
                let timestamp = vm.get_executor().global_clock as u32;

                match step(vm, instruction, pc, timestamp, true) {
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
    ad: &[u8],
    public_input: &[u8],
    private_input: &[u8],
) -> Result<(View, BBTrace)> {
    let mut harvard = HarvardEmulator::from_elf(&elf, public_input, private_input);
    harvard.get_executor_mut().capture_logs(true);

    match harvard.execute(false) {
        Err(VMError::VMExited(_)) => {
            // todo: consistency check i/o between harvard and linear?
            let mut linear = LinearEmulator::from_harvard(&harvard, elf, ad, private_input)?;

            let mut trace = BBTrace {
                memory_layout: linear.memory_layout,
                start: 0,
                blocks: Vec::new(),
            };

            loop {
                match bb_step(&mut linear) {
                    (Some(block), Ok(())) => trace.blocks.push(block),
                    (Some(block), Err(e)) => {
                        if !block.steps.is_empty() {
                            trace.blocks.push(block);
                        }

                        match e {
                            VMError::VMExited(_) => {
                                let mut view = linear.finalize();
                                view.add_logs(&harvard);
                                return Ok((view, trace));
                            }
                            _ => return Err(e),
                        }
                    }
                    (None, Err(e)) => return Err(e),
                    (None, Ok(())) => unreachable!(),
                }
            }
        }
        Err(e) => Err(e),
        Ok(_) => unreachable!(),
    }
}

/// Similar to `bb_trace`, but uses HarvardEmulator and supports Intermediate Representation (IR) as input instead of an ELF file.
pub fn bb_trace_direct(basic_blocks: &Vec<BasicBlock>) -> Result<(View, BBTrace)> {
    let mut harvard = HarvardEmulator::from_basic_blocks(basic_blocks);

    let mut trace = BBTrace {
        memory_layout: LinearMemoryLayout::default(), // dummy
        start: 0,
        blocks: Vec::new(),
    };

    loop {
        match bb_step(&mut harvard) {
            (Some(block), Ok(())) => trace.blocks.push(block),
            (Some(block), Err(e)) => {
                if !block.steps.is_empty() {
                    trace.blocks.push(block);
                }

                match e {
                    VMError::VMExited(_) => return Ok((harvard.finalize(), trace)),
                    _ => return Err(e),
                }
            }
            (None, Err(VMError::VMOutOfInstructions)) => return Ok((harvard.finalize(), trace)),
            (None, Err(e)) => return Err(e),
            (None, Ok(())) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        read_testing_elf_from_path,
        riscv::{BuiltinOpcode, Opcode, Register},
    };
    use nexus_common::constants::ELF_TEXT_START;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_k1_trace_nexus_rt_binary() {
        let elf_file = read_testing_elf_from_path!("/test/fib_10.elf");
        let (_, trace) = k_trace(elf_file, &[], &[], &[], 1).unwrap(); // todo: unit test over a program with complex i/o to enable checking view

        // check the first block
        let block = trace.block(0).unwrap();

        assert_eq!(block.steps.len(), 1);
        assert_eq!(trace.block(1).unwrap().regs[Register::X3], 0x2088); // check global pointer is updated

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 1);
        assert_eq!(step.pc, ELF_TEXT_START);
        assert_eq!(step.next_pc, ELF_TEXT_START + 4);
        assert_eq!(step.raw_instruction, 0x00002197);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(0x2088));
        assert!(step.memory_records.is_empty());

        let block = trace.block(2).unwrap();
        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 3);
        assert_eq!(step.pc, 0x90);
        assert_eq!(step.next_pc, 0x94);
        assert_eq!(step.raw_instruction, 0x80400117);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(0x80400090));
        assert_eq!(step.memory_records.len(), 0);

        let block = trace.block(trace.blocks.len() - 1).unwrap();

        assert_eq!(block.steps.len(), 1);

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, trace.blocks.len() as u32);
        assert_eq!(step.pc, 0xCC);
        assert_eq!(step.next_pc, 0xCC);
        assert_eq!(step.raw_instruction, 0x00000073);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }

    #[test]
    #[serial]
    fn test_k8_trace_nexus_rt_binary() {
        let elf_file = read_testing_elf_from_path!("/test/fib_10.elf");
        let (_, trace) = k_trace(elf_file, &[], &[], &[], 8).unwrap(); // todo: unit test over a program with complex i/o to enable checking view

        // check the first block
        let block = trace.block(0).unwrap();

        assert_eq!(block.steps.len(), 8);
        assert_eq!(trace.block(1).unwrap().regs[Register::X3], 0x1F30); // check global pointer is updated (also after `addi gp, gp, -264` at timestamp 2)

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 1);
        assert_eq!(step.pc, 0x88);
        assert_eq!(step.next_pc, 0x8C);
        assert_eq!(step.raw_instruction, 0x00002197);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(0x2088));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(1).unwrap();

        assert_eq!(block.steps.len(), 8);

        let step = block.steps[4].clone();

        assert_eq!(step.timestamp, 13);
        assert_eq!(step.pc, 0x25C);
        assert_eq!(step.next_pc, 0x260);
        assert_eq!(step.raw_instruction, 0xFA010113);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ADDI));
        assert_eq!(step.result, Some(0x1A50));
        assert_eq!(step.memory_records.len(), 0);

        let block = trace.block(trace.blocks.len() - 1).unwrap();

        assert!(block.steps.len() <= 8);

        let step = block.steps.last().unwrap().clone();

        assert_eq!(
            step.timestamp,
            (8 * (trace.blocks.len() as u32 - 1) + block.steps.len() as u32)
        );
        assert_eq!(step.pc, 0xCC);
        assert_eq!(step.next_pc, 0xCC);
        assert_eq!(step.raw_instruction, 0x00000073);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }

    #[test]
    #[serial]
    fn test_bb_trace_nexus_rt_binary() {
        let elf_file = read_testing_elf_from_path!("/test/fib_10.elf");
        let (_, trace) = bb_trace(elf_file, &[], &[], &[]).unwrap(); // todo: unit test over a program with complex i/o to enable checking view

        // check the first block
        let block = trace.block(0).unwrap();

        assert_eq!(trace.block(1).unwrap().regs[Register::X3], 0x1F30); // check global pointer is updated (also after `addi gp, gp, -264` at timestamp 2)

        let step = block.steps[0].clone();

        assert_eq!(step.timestamp, 1);
        assert_eq!(step.pc, ELF_TEXT_START);
        assert_eq!(step.next_pc, ELF_TEXT_START + 4);
        assert_eq!(step.raw_instruction, 0x00002197);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::AUIPC));
        assert_eq!(step.result, Some(8328));
        assert!(step.memory_records.is_empty());

        // check a memory operation
        let block = trace.block(4).unwrap();

        let step = block.steps[1].clone();

        assert_eq!(step.timestamp, 75);
        assert_eq!(step.pc, 4756);
        assert_eq!(step.next_pc, 4760);
        assert_eq!(step.raw_instruction, 0x6050A63);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::BEQ));
        assert_eq!(step.result, Some(4760));
        assert_eq!(step.memory_records.len(), 0);

        assert!(step.memory_records.is_empty());

        let block = trace.block(trace.blocks.len() - 1).unwrap();

        assert!(block.steps.len() <= 9);

        let step = block.steps.last().unwrap().clone();

        assert_eq!(step.pc, 0xCC);
        assert_eq!(step.next_pc, 0xCC);
        assert_eq!(step.raw_instruction, 0x00000073);
        assert_eq!(step.instruction.opcode, Opcode::from(BuiltinOpcode::ECALL));
        assert_eq!(step.result, Some(0));
        assert!(step.memory_records.is_empty());
    }

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_bb_trace_direct_from_basic_block_ir() {
        let basic_blocks = setup_basic_block_ir();
        let (_, trace) = bb_trace_direct(&basic_blocks).expect("Failed to create trace");

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

    #[test]
    fn test_k1_trace_direct_from_basic_block_ir() {
        let basic_block = setup_basic_block_ir();
        let k = 1;
        let (_, trace) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        let first_block = trace.blocks.first().expect("No blocks in trace");
        let first_step = first_block.steps.first().expect("No steps in trace");
        assert_eq!(first_step.result, Some(1), "Unexpected Fibonacci result",);

        let last_block = trace.blocks.last().expect("No blocks in trace");
        let last_step = last_block.steps.last().expect("No steps in trace");

        // The result of 30th Fibonacci number is 1346269
        assert_eq!(
            last_step.result,
            Some(1346269),
            "Unexpected Fibonacci result"
        );
    }

    #[test]
    fn test_k4_trace_direct_from_basic_block_ir() {
        let basic_block = setup_basic_block_ir();
        // For k=4, the trace block is completed by padding with UNIMPL instructions if necessary.
        let k = 4;

        let (_, trace) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        let first_block = trace.blocks.first().expect("No blocks in trace");
        let first_step = first_block.steps.first().expect("No steps in trace");
        assert_eq!(first_step.result, Some(1), "Unexpected Fibonacci result",);

        let last_block = trace.blocks.last().expect("No blocks in trace");

        // The result of 30th Fibonacci number is 1346269
        assert_eq!(
            last_block.steps[2].result,
            Some(1346269),
            "Unexpected Fibonacci result"
        );
        let last_step = last_block.steps.last().expect("No steps in trace");

        // The last step is padded with UNIMPL instruction
        assert_eq!(
            last_step.instruction,
            Instruction::unimpl(),
            "Unexpected instruction"
        );
        assert_eq!(last_step.result, None, "Unexpected Fibonacci result");
    }

    #[test]
    fn test_k8_trace_direct_timestamp_tick_after_instruction_ended() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::nop(),
            Instruction::nop(),
        ])];

        let k = 8;
        let (_, trace) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        let first_block = trace.blocks.first().expect("No blocks in trace");
        let first_step = first_block.steps.first().expect("No steps in trace");
        let last_step = first_block.steps.last().expect("No steps in trace");
        assert_eq!(first_step.timestamp, 1, "Unexpected timestamp");
        // The timestamp must continue to tick even if the program is ended.
        assert_eq!(
            last_step.timestamp,
            1 + k as u32,
            "Unexpected timestamp for the last step"
        );
    }
}
