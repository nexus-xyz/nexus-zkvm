//! A Virtual Machine for RISC-V

use crate::error::*;
use crate::rv32::{RV32, parse::*};
use super::memory::path::Path;
use super::eval::*;

// ArkWorks macros are not hygenic
mod ark_confusion {
    use serde::{Serialize, Deserialize};
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use super::{Regs, Path};

    #[derive(Default, Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Trace {
        pub k: usize,
        pub start: usize,
        pub blocks: Vec<Block>,
    }

    #[derive(Default, Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Block {
        pub regs: Regs,
        pub steps: Vec<Step>,
    }

    #[derive(Default, Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Step {
        pub inst: u32,
        pub Z: u32,
        pub PC: u32,
        #[serde(with = "crate::ark_serde")]
        pub pc_path: Path,
        #[serde(with = "crate::ark_serde")]
        pub read_path: Option<Path>,
        #[serde(with = "crate::ark_serde")]
        pub write_path: Option<Path>,
    }
}
pub use ark_confusion::*;

impl Trace {
    pub fn split_by(&self, n: usize) -> impl Iterator<Item = Self> + '_ {
        let mut index = 0;
        self.blocks.chunks(n).map(move |bs| {
            let start = index;
            index += n;
            Trace { k: self.k, start, blocks: bs.to_vec() }
        })
    }

    pub fn get(&self, n: usize) -> Self {
        Trace {
            k: self.k,
            start: n,
            blocks: vec![self.blocks[n].clone()],
        }
    }
}

fn step(vm: &mut VM) -> Result<Step> {
    eval_inst(vm)?;
    let step = Step {
        inst: vm.inst.word,
        Z: vm.Z,
        PC: vm.regs.pc,
        pc_path: vm.pc_path.as_ref().unwrap().clone(),
        read_path: vm.read_path.clone(),
        write_path: vm.write_path.clone(),
    };
    Ok(step)
}

fn k_step(vm: &mut VM, k: usize) -> Result<Block> {
    let mut block = Block { regs: vm.regs.clone(), steps: Vec::new() };

    for _ in 0..k {
        block.steps.push(step(vm)?);
    }

    Ok(block)
}

pub fn trace(vm: &mut VM, k: usize, pow: bool) -> Result<Trace> {
    // check here so we can safely unwrap paths later
    if vm.mem.root().is_none() {
        panic!("trace requires merkle hashes");
    }
    let mut trace = Trace { k, start: 0, blocks: Vec::new() };

    loop {
        let block = k_step(vm, k)?;
        trace.blocks.push(block);

        if vm.inst.inst == RV32::UNIMP {
            if pow {
                let count = trace.blocks.len();
                if count.next_power_of_two() == count {
                    break;
                }
            } else {
                break;
            }
        }
    }
    Ok(trace)
}

#[derive(Default)]
pub struct Witness {
    pub regs: Regs,

    pub inst: u32,
    pub J: u32,
    pub shamt: u32,
    pub rs1: u32,
    pub rs2: u32,
    pub rd: u32,
    pub I: u32,

    pub X: u32,
    pub Y: u32,
    pub Z: u32,
    pub PC: u32,

    pub pc_path: Path,
    pub read_path: Path,
    pub write_path: Path,
}

impl Block {
    fn iter(&self) -> BlockIter<'_> {
        BlockIter::new(self)
    }
}

impl<'a> IntoIterator for &'a Block {
    type Item = Witness;
    type IntoIter = BlockIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct BlockIter<'a> {
    regs: Regs,
    block: &'a Block,
    index: usize,
}

impl BlockIter<'_> {
    fn new(b: &Block) -> BlockIter<'_> {
        BlockIter { regs: b.regs.clone(), block: b, index: 0 }
    }
}

impl Iterator for BlockIter<'_> {
    type Item = Witness;

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
        w.PC = s.PC;

        w.pc_path = s.pc_path.clone();
        w.read_path = s.read_path.as_ref().unwrap_or(&w.pc_path).clone();
        w.write_path = s.write_path.as_ref().unwrap_or(&w.read_path).clone();

        self.regs.pc = w.PC;
        self.regs.x[w.rd as usize] = w.Z;
        self.index += 1;
        Some(w)
    }
}

// Note: this is temporary and will not be necessary once
// we move to the NVM.
fn parse_alt(regs: &Regs, word: u32) -> Witness {
    let mut w = Witness::default();

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
