//! A Virtual Machine for RISC-V

use crate::error::*;
use crate::rv32::{parse::*, *};
use super::mem::*;
use VMError::*;

// for ecall
use std::io::Write;

/// virtual machine state
#[derive(Default)]
pub struct VM {
    /// ISA registers
    pub regs: Regs,
    /// machine memory
    pub mem: Mem,
    /// current instruction
    pub inst: Inst,
    /// destination register
    pub rd: u32,
    /// internal result register
    pub Z: u32,
    /// internal program counter
    pub PC: u32,
}

// ArkWorks macros are not hygenic
mod ark_confusion {
    use serde::{Serialize, Deserialize};
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

    /// ISA defined registers
    #[derive(Clone, Default, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Regs {
        /// ISA defined program counter register
        pub pc: u32,
        /// ISA defined registers x0-x31
        pub x: [u32; 32],
    }
}
pub use ark_confusion::*;

impl VM {
    pub fn new(pc: u32) -> Self {
        let mut vm = Self::default();
        vm.regs.pc = pc;
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
    pub fn init_memory(&mut self, addr: u32, bytes: &[u8]) {
        // slow, but simple
        for (i, b) in bytes.iter().enumerate() {
            self.mem.sb(addr + (i as u32), *b as u32);
        }
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

/// finalize previous instruction and update machine state.
pub fn eval_writeback(vm: &mut VM) {
    vm.set_reg(vm.rd, vm.Z);
    vm.regs.pc = vm.PC;
}

/// evaluate next instruction
pub fn eval_inst(vm: &mut VM) -> Result<()> {
    vm.inst = parse_inst(vm.regs.pc, vm.mem.rd_page(vm.regs.pc))?;

    // initialize micro-architecture state
    vm.rd = 0;
    vm.Z = 0;
    vm.PC = 0;

    match vm.inst.inst {
        LUI { rd, imm } => {
            vm.rd = rd;
            vm.Z = imm;
        }
        AUIPC { rd, imm } => {
            vm.rd = rd;
            vm.Z = add32(vm.regs.pc, imm);
        }
        JAL { rd, imm } => {
            vm.rd = rd;
            vm.Z = add32(vm.regs.pc, 4);
            vm.PC = add32(vm.regs.pc, imm);
        }
        JALR { rd, rs1, imm } => {
            let X = vm.get_reg(rs1);
            vm.rd = rd;
            vm.Z = add32(vm.regs.pc, 4);
            vm.PC = add32(X, imm);
        }
        BR { bop, rs1, rs2, imm } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);

            if br_op(bop, X, Y) {
                vm.PC = add32(vm.regs.pc, imm);
            }
        }
        LOAD { lop, rd, rs1, imm } => {
            let X = vm.get_reg(rs1);
            vm.rd = rd;

            let addr = add32(X, imm);
            match lop {
                LB => vm.Z = vm.mem.lb(addr),
                LH => vm.Z = vm.mem.lh(addr),
                LW => vm.Z = vm.mem.lw(addr),
                LBU => vm.Z = vm.mem.lbu(addr),
                LHU => vm.Z = vm.mem.lhu(addr),
            }
        }
        STORE { sop, rs1, rs2, imm } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);

            let addr = add32(X, imm);
            match sop {
                SB => vm.mem.sb(addr, Y),
                SH => vm.mem.sh(addr, Y),
                SW => vm.mem.sw(addr, Y),
            }
        }
        ALUI { aop, rd, rs1, imm } => {
            vm.rd = rd;
            let X = vm.get_reg(rs1);
            vm.Z = alu_op(aop, X, imm);
        }
        ALU { aop, rd, rs1, rs2 } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);
            vm.rd = rd;
            vm.Z = alu_op(aop, X, Y);
        }
        FENCE | EBREAK => {}
        ECALL => {
            let num = vm.regs.x[18]; // s2 = x8  syscall number
            let a0 = vm.regs.x[10]; // a0 = x10
            let a1 = vm.regs.x[11]; // a1 = x11

            // write_log
            if num == 1 {
                let mut stdout = std::io::stdout();
                for addr in a0..a0 + a1 {
                    let b = vm.mem.lb(addr) as u8;
                    stdout.write_all(&[b])?;
                }
                let _ = stdout.flush();
            } else {
                return Err(UnknownECall(vm.regs.pc, num));
            }
        }
        UNIMP => {
            vm.PC = vm.inst.pc;
        }
    }

    if vm.PC == 0 {
        vm.PC = add32(vm.inst.pc, vm.inst.len);
    }
    Ok(())
}
