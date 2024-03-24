//! A Virtual Machine for RISC-V

use nexus_vm::{
    instructions::Width,
    memory::{paged::Paged, Memory},
    syscalls::Syscalls,
};

use crate::error::*;
use crate::rv32::{parse::*, *};

/// virtual machine state
#[derive(Default)]
pub struct VM {
    /// ISA registers
    pub regs: Regs,
    /// Syscall implementation
    pub syscalls: Syscalls,
    /// machine memory
    pub mem: Paged,
    /// current instruction
    pub inst: Inst,
    /// internal result register
    pub Z: u32,
}

/// ISA defined registers
#[derive(Debug, PartialEq, Default)]
pub struct Regs {
    /// ISA defined program counter register
    pub pc: u32,
    /// ISA defined registers x0-x31
    pub x: [u32; 32],
}

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
    pub fn init_memory(&mut self, addr: u32, bytes: &[u8]) -> Result<()> {
        // slow, but simple
        for (i, b) in bytes.iter().enumerate() {
            self.mem.store(Width::B, addr + (i as u32), *b as u32)?;
        }
        Ok(())
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
pub fn eval_inst(vm: &mut VM) -> Result<()> {
    let slice = vm.mem.load(Width::W, vm.regs.pc)?.0.to_le_bytes();
    vm.inst = parse_inst(vm.regs.pc, &slice)?;

    // initialize micro-architecture state
    vm.Z = 0;
    let mut RD = 0u32;
    let mut PC = 0;

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
            match lop {
                LB => vm.Z = vm.mem.load(Width::B, addr)?.0,
                LH => vm.Z = vm.mem.load(Width::H, addr)?.0,
                LW => vm.Z = vm.mem.load(Width::W, addr)?.0,
                LBU => vm.Z = vm.mem.load(Width::BU, addr)?.0,
                LHU => vm.Z = vm.mem.load(Width::HU, addr)?.0,
            }
        }
        STORE { sop, rs1, rs2, imm } => {
            let X = vm.get_reg(rs1);
            let Y = vm.get_reg(rs2);

            let addr = add32(X, imm);
            match sop {
                SB => vm.mem.store(Width::B, addr, Y)?,
                SH => vm.mem.store(Width::H, addr, Y)?,
                SW => vm.mem.store(Width::W, addr, Y)?,
            };
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
            vm.syscalls.syscall(vm.regs.pc, vm.regs.x, &vm.mem)?;
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
