//! A Virtual Machine for RISC-V

use crate::{
    error::*,
    memory::Memory,
    rv32::{parse::*, *},
    syscalls::Syscalls,
};

use std::collections::HashSet;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// virtual machine state
#[derive(Default)]
pub struct NexusVM<M: Memory> {
    /// ISA registers
    pub regs: Regs,
    /// Syscall implementation
    pub syscalls: Syscalls,
    /// current instruction
    pub inst: Inst,
    /// internal result register
    pub Z: u32,
    /// used instruction sets
    pub instruction_sets: HashSet<InstructionSet>,
    /// Machine memory.
    pub mem: M,
    /// Memory proof for current instruction at pc
    pub pc_proof: M::Proof,
    /// Memory proof for load/store instructions.
    pub read_proof: Option<M::Proof>,
    /// Memory proof for store instructions.
    pub write_proof: Option<M::Proof>,
}

/// ISA defined registers
#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct Regs {
    /// ISA defined program counter register
    pub pc: u32,
    /// ISA defined registers x0-x31
    pub x: [u32; 32],
}

impl<M: Memory> NexusVM<M> {
    pub fn new(pc: u32) -> Self {
        let mut vm = Self::default();

        vm.regs.pc = pc;
        vm.instruction_sets = HashSet::new();

        vm
    }

    /// get value of register r
    pub fn get_reg(&self, r: u32) -> u32 {
        if r == 0 {
            0
        } else {
            self.regs.x[r as usize]
        }
    }

    /// set value of register r
    pub fn set_reg(&mut self, r: u32, val: u32) {
        if r != 0 {
            self.regs.x[r as usize] = val;
        }
    }

    /// initialize memory from slice
    pub fn init_memory(&mut self, addr: u32, bytes: &[u8]) -> Result<()> {
        // slow, but simple
        for (i, b) in bytes.iter().enumerate() {
            self.mem.store(SOP::SB, addr + (i as u32), *b as u32)?;
        }
        Ok(())
    }
}

// A simple, stable peephole optimizer for local constant propagation.
//
// Introduced for old 32-bit -> 64-bit translation, currently unused.
#[allow(dead_code)]
fn peephole(insn: &mut [Inst]) {
    for i in 0..insn.len() {
        match const_prop(&insn[i..]) {
            None => (),
            Some(v) => {
                for (j, x) in v.iter().enumerate() {
                    insn[i + j] = *x;
                }
            }
        }
    }
}

#[allow(dead_code)]
fn const_prop(insn: &[Inst]) -> Option<Vec<Inst>> {
    match insn {
        [Inst {
            pc: pc1,
            inst: RV32::AUIPC { rd: rd1, imm: imm1 },
            ..
        }, Inst {
            pc: pc2,
            inst: RV32::JALR { rd: rd2, rs1, imm: imm2 },
            ..
        }, ..]
            if rd1 == rs1 =>
        {
            let target = add32(add32(*pc1, *imm1), *imm2);
            Some(vec![
                Inst {
                    pc: *pc1,
                    len: 4,
                    word: 0,
                    inst: RV32::ALUI { aop: AOP::ADD, rd: 0, rs1: 0, imm: 0 },
                },
                Inst {
                    pc: *pc2,
                    len: 4,
                    word: 0,
                    inst: RV32::JALR { rd: *rd2, rs1: 0, imm: target },
                },
            ])
        }
        _ => None,
    }
}

fn add32(a: u32, b: u32) -> u32 {
    a.overflowing_add(b).0
}

fn sub32(a: u32, b: u32) -> u32 {
    a.overflowing_sub(b).0
}

fn br_op(bop: BOP, x: u32, y: u32) -> bool {
    match bop {
        BEQ => x == y,
        BNE => x != y,
        BLT => (x as i32) < (y as i32),
        BGE => (x as i32) >= (y as i32),
        BLTU => x < y,
        BGEU => x >= y,
    }
}

fn alu_op(aop: AOP, x: u32, y: u32) -> u32 {
    let shamt = y & 0x1f;
    match aop {
        ADD => add32(x, y),
        SUB => sub32(x, y),
        SLT => ((x as i32) < (y as i32)) as u32,
        SLTU => (x < y) as u32,
        SLL => x << shamt,
        SRL => x >> shamt,
        SRA => ((x as i32) >> shamt) as u32,
        AND => x & y,
        OR => x | y,
        XOR => x ^ y,
    }
}

/// evaluate next instruction
pub fn eval_inst(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    let (word, proof) = vm.mem.read_inst(vm.regs.pc)?;
    vm.inst = parse_inst(vm.regs.pc, &word.to_le_bytes())?;

    // initialize micro-architecture state
    vm.Z = 0;
    let mut RD = 0u32;
    let mut PC = 0;

    vm.pc_proof = proof;
    vm.read_proof = None;
    vm.write_proof = None;

    vm.instruction_sets.insert(vm.inst.inst.instruction_set());

    match vm.inst.inst {
        LUI { rd, imm } => {
            RD = rd;
            vm.Z = imm;
        }
        AUIPC { rd, imm } => {
            RD = rd;
            vm.Z = add32(vm.regs.pc, imm);
        }
        JAL { rd, imm } => {
            RD = rd;
            vm.Z = add32(vm.regs.pc, 4);
            PC = add32(vm.regs.pc, imm);
        }
        JALR { rd, rs1, imm } => {
            let X = vm.get_reg(rs1);
            RD = rd;
            vm.Z = add32(vm.regs.pc, 4);
            PC = add32(X, imm);
        }
        BR { bop, rs1, rs2, imm } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);

            if br_op(bop, X, Y) {
                PC = add32(vm.regs.pc, imm);
            }
        }
        LOAD { lop, rd, rs1, imm } => {
            let X = vm.get_reg(rs1);
            RD = rd;

            let addr = add32(X, imm);
            let (val, proof) = vm.mem.load(lop, addr)?;
            vm.read_proof = Some(proof);
            vm.Z = val;
        }
        STORE { sop, rs1, rs2, imm } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);

            let addr = add32(X, imm);
            let lop = match sop {
                SB => LB,
                SH => LH,
                SW => LW,
            };

            let (_, proof) = vm.mem.load(lop, addr)?;
            vm.read_proof = Some(proof);
            vm.write_proof = Some(vm.mem.store(sop, addr, Y)?);
        }
        ALUI { aop, rd, rs1, imm } => {
            RD = rd;
            let X = vm.get_reg(rs1);
            vm.Z = alu_op(aop, X, imm);
        }
        ALU { aop, rd, rs1, rs2 } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);
            RD = rd;
            vm.Z = alu_op(aop, X, Y);
        }
        FENCE | EBREAK => {}
        ECALL => {
            // Per the RISC-V ISA, for an ecall `rd = 0` and the system determines
            // how to return a value, e.g. by modifying register `x10` (aka `a0`).
            //
            // For the NVM ISA, we formalize this by setting `rd = 10` and having each
            // ecall modify `x10`, even if to just write zero. By doing so, we know
            // that `rd` points to the modified register, and so we will always
            // generate the R1CS circuit constraints correctly.
            RD = 10;

            vm.Z = vm.syscalls.syscall(vm.regs.pc, vm.regs.x, &vm.mem)?;
        }
        UNIMP => {
            PC = vm.inst.pc;
        }
    }

    if PC == 0 {
        PC = add32(vm.inst.pc, vm.inst.len);
    }
    vm.set_reg(RD, vm.Z);
    vm.regs.pc = PC;
    Ok(())
}
