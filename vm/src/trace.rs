//! Nexus VM program traces
//!
//! A trace is generated by running a Nexus VM program.
//! A `Trace` holds a number of `Blocks`, and each `Block` holds
//! a number of `Steps`. The number of steps in each block
//! (also referred to as `k`), corresponds to the instructions
//! per folding step. Thus, each block corresponds to one
//! folding step.
//!
//! A `Trace` can be divided at block boundaries and each subtrace
//! proved independently of the others (when using PCD). Each `Block`
//! contains enough information to reconstruct the `Witness` for each
//! step contained in the block. The witnesses can be reconstructed
//! by iterating over the steps in the block.

use num_traits::FromPrimitive;

use crate::circuit::F;
use crate::error::Result;
use crate::eval::{eval_inst, NexusVM, Regs};
use crate::rv32::{Inst, RV32::UNIMP, parse::*};
use crate::memory::{Memory, MemoryProof};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Represents a program trace.
#[derive(Default, Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Trace<P: MemoryProof> {
    /// Steps per fold/block.
    pub k: usize,
    /// First block in this (sub)trace.
    pub start: usize,
    /// The blocks contained in this trace.
    pub blocks: Vec<Block<P>>,
}

/// A seqeunce of program steps.
#[derive(Default, Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Block<P: MemoryProof> {
    /// Starting register file for this block.
    pub regs: Regs,
    /// Sequence of `k` steps contained in this block.
    pub steps: Vec<Step<P>>,
}

/// A program step.
#[derive(Default, Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Step<P: MemoryProof> {
    /// Encoded NexusVM instruction.
    pub inst: u32,
    /// Result of instruction evaluation.
    pub Z: u32,
    /// Next program counter, for jump and branch instructions.
    pub PC: Option<u32>,
    /// Merkle proof for instruction at pc.
    #[serde(with = "crate::ark_serde")]
    pub pc_proof: P,
    /// Merkle proof for read instructions.
    #[serde(with = "crate::ark_serde")]
    pub read_proof: Option<P>,
    /// Merkle proof for write instructions.
    #[serde(with = "crate::ark_serde")]
    pub write_proof: Option<P>,
}

impl<P: MemoryProof> Trace<P> {
    /// Split a trace into subtraces with `n` blocks each. Note, the
    /// final subtrace may contain fewer than `n` blocks.
    pub fn split_by(&self, n: usize) -> impl Iterator<Item = Self> + '_ {
        let mut index = 0;
        self.blocks.chunks(n).map(move |bs| {
            let start = index;
            index += n;
            Trace { k: self.k, start, blocks: bs.to_vec() }
        })
    }

    /// Return block with index `n`, if it is contained in this (sub)trace.
    pub fn block(&self, n: usize) -> Option<&Block<P>> {
        if self.start > n || self.start + self.blocks.len() <= n {
            return None;
        }
        Some(&self.blocks[n - self.start])
    }

    /// Create a subtrace containing only block `n`.
    pub fn get(&self, n: usize) -> Option<Self> {
        Some(Trace {
            k: self.k,
            start: n,
            blocks: vec![self.block(n)?.clone()],
        })
    }

    /// Return the circuit input for block at index `n`.
    /// This vector is compatible with the NexusVM step circuit.
    pub fn input(&self, n: usize) -> Option<Vec<F>> {
        let b = self.block(n)?;
        let mut v = Vec::new();
        v.push(F::from(b.regs.pc));
        for x in b.regs.x {
            v.push(F::from(x));
        }
        v.push(b.steps[0].pc_proof.commit());
        Some(v)
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

// Generate a `Step` by evaluating the next instruction of `vm`.
fn step<M: Memory>(vm: &mut NexusVM<M>) -> Result<Step<M::Proof>> {
    let pc = vm.regs.pc;
    eval_inst(vm)?;
    let step = Step {
        inst: vm.inst.word,
        Z: vm.Z,
        PC: if vm.regs.pc == pc + 8 { None } else { Some(vm.regs.pc) },
        pc_proof: vm.pc_proof.clone(),
        read_proof: vm.read_proof.clone(),
        write_proof: vm.write_proof.clone(),
    };
    Ok(step)
}

// Generate a `Block` by evaluating `k` steps of `vm`.
fn k_step<M: Memory>(vm: &mut NexusVM<M>, k: usize) -> Result<Block<M::Proof>> {
    let mut block = Block {
        regs: vm.regs.clone(),
        steps: Vec::new(),
    };

    for _ in 0..k {
        block.steps.push(step(vm)?);
    }

    Ok(block)
}

/// Generate a program trace by evaluating `vm`, using `k` steps
/// per block. If `pow` is true, the total number of steps will
/// be rounded up to the nearest power of two by inserting UNIMP
/// instructions.
pub fn trace<M: Memory>(vm: &mut NexusVM<M>, k: usize, pow: bool) -> Result<Trace<M::Proof>> {
    let mut trace = Trace { k, start: 0, blocks: Vec::new() };

    loop {
        let block = k_step(vm, k)?;
        trace.blocks.push(block);

        if vm.inst.inst == UNIMP {
            if pow {
                let count = trace.blocks.len();
                if count.next_power_of_two() == count + 1 {
                    break;
                }
            } else {
                break;
            }
        }
    }
    Ok(trace)
}

/// Witness for a single VM step.
#[derive(Default, Debug)]
pub struct Witness<P: MemoryProof> {
    /// Initial register file.
    pub regs: Regs,
    /// Instruction being executed.
    pub inst: u32,
    pub J: u32,
    pub shamt: u32,
    pub rs1: u32,
    pub rs2: u32,
    pub rd: u32,
    pub I: u32,
    /// First argument value.
    pub X: u32,
    /// Second argument value.
    pub Y: u32,
    /// Result of instuction.
    pub Z: u32,
    /// Next program counter.
    pub PC: u32,
    /// Proof for reading instruction at pc.
    pub pc_proof: P,
    /// Proof for load instructions.
    pub read_proof: P,
    /// Proof for store instructions.
    pub write_proof: P,
}

impl<P: MemoryProof> Block<P> {
    pub fn iter(&self) -> BlockIter<'_, P> {
        BlockIter::new(self)
    }
}

impl<'a, P: MemoryProof> IntoIterator for &'a Block<P> {
    type Item = Witness<P>;
    type IntoIter = BlockIter<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct BlockIter<'a, P: MemoryProof> {
    regs: Regs,
    block: &'a Block<P>,
    index: usize,
}

impl<P: MemoryProof> BlockIter<'_, P> {
    fn new(b: &Block<P>) -> BlockIter<'_, P> {
        BlockIter {
            regs: b.regs.clone(),
            block: b,
            index: 0,
        }
    }
}

impl<P: MemoryProof> Iterator for BlockIter<'_, P> {
    type Item = Witness<P>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.block.steps.len() {
            return None;
        }

        let s = &self.block.steps[self.index];
        let inst = parse_u32(s.inst).unwrap();
        let mut w = parse_alt(&self.block.regs, s.inst);
        w.regs = self.regs.clone();
        w.inst = s.inst;
        w.J = inst.index_j();
        w.X = w.regs.x[w.rs1 as usize];
        w.Y = w.regs.x[w.rs2 as usize];
        w.Z = s.Z;
        w.PC = if let Some(pc) = s.PC { pc } else { self.regs.pc + 8 };

        w.pc_proof = s.pc_proof.clone();
        w.read_proof = s.read_proof.as_ref().unwrap_or(&w.pc_proof).clone();
        w.write_proof = s.write_proof.as_ref().unwrap_or(&w.read_proof).clone();

        self.regs.pc = w.PC;
        self.regs.x[w.rd as usize] = w.Z;
        self.index += 1;
        Some(w)
    }
}

fn parse_alt<P: MemoryProof>(regs: &Regs, word: u32) -> Witness<P> {
    let mut w = Witness::<P>::default();

    match opcode(word) {
        OPC_LUI => {
            w.rd = rd(word);
            w.I = immU(word);
        }
        OPC_AUIPC => {
            w.rd = rd(word);
            w.I = immU(word);
        }
        OPC_JAL => {
            w.rd = rd(word);
            w.I = immJ(word);
        }
        OPC_JALR => {
            w.rd = rd(word);
            w.rs1 = rs1(word);
            w.I = immI(word);
        }
        OPC_BR => {
            w.rs1 = rs1(word);
            w.rs2 = rs2(word);
            w.I = immB(word);
        }
        OPC_LOAD => {
            w.rd = rd(word);
            w.rs1 = rs1(word);
            w.I = immI(word);
        }
        OPC_STORE => {
            w.rs1 = rs1(word);
            w.rs2 = rs2(word);
            w.I = immS(word);
        }
        OPC_ALUI => {
            w.rd = rd(word);
            w.rs1 = rs1(word);
            w.I = immA(word);
            w.shamt = w.I & 0x1f;
        }
        OPC_ALU => {
            w.rd = rd(word);
            w.rs1 = rs1(word);
            w.rs2 = rs2(word);
            w.shamt = regs.x[w.rs2 as usize] & 0x1f;
        }
        _ => (),
    };
    w
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{machines::loop_vm, memory::paged::Paged, memory::trie::MerkleTrie};

    // basic check that tracing and iteration succeeds
    fn trace_test_machine(mut nvm: NexusVM<impl Memory>) {
        let tr = trace(&mut nvm, 1, false).unwrap();
        let mut pc = 0u32;
        for b in tr.blocks {
            for w in b.iter() {
                pc = w.regs.pc;
            }
        }
        assert_eq!(nvm.regs.pc, pc);
    }

    #[test]
    fn trace_test_machines() {
        trace_test_machine(loop_vm::<Paged>(5));
        trace_test_machine(loop_vm::<MerkleTrie>(5));
    }
}
