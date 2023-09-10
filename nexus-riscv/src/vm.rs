//! A Virtual Machine for RISC-V

mod mem;
use crate::error::*;
use crate::rv32::{parse::*, *};
pub use mem::*;
use VMError::*;

// for ecall
use std::io::Write;

/// virtual machine state
#[derive(Default)]
pub struct VM {
    // Code memory as a vector
    pub code: Vec<Inst>,
    /// ISA defined program counter register
    pub pc: u32,
    /// ISA defined registers x0-x31
    pub regs: [u32; 32],
    /// machine memory
    pub mem: Mem,
    /// current instruction
    pub inst: Inst,
    /// shift amount
    pub shamt: u32,
    /// argument register 1
    pub rs1: u32,
    /// argument register 2
    pub rs2: u32,
    /// destination register
    pub rd: u32,
    /// immediate value from instruction
    pub I: u32,
    /// internal argument register
    pub X: u32,
    /// internal argument register
    pub Y: u32,
    /// internal result register
    pub Z: u32,
    /// internal program counter
    pub PC: u32,
}

impl VM {
    /// get value of register r
    pub fn get_reg(&self, r: u32) -> u32 {
        if r == 0 {
            0
        } else {
            self.regs[r as usize]
        }
    }

    /// set value of register r
    pub fn set_reg(&mut self, r: u32, val: u32) {
        if r != 0 {
            self.regs[r as usize] = val;
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
    vm.pc = vm.PC;
}

/// evaluate next instruction
pub fn eval_inst(vm: &mut VM) -> Result<()> {
    vm.inst = parse_inst(vm.pc, vm.mem.rd_page(vm.pc))?;

    // initialize micro-architecture state
    vm.shamt = 0;
    vm.rs1 = 0;
    vm.rs2 = 0;
    vm.rd = 0;
    vm.X = 0;
    vm.Y = 0;
    vm.I = 0;
    vm.Z = 0;
    vm.PC = 0;

    match vm.inst.inst {
        LUI { rd, imm } => {
            vm.rd = rd;
            vm.I = imm;
            vm.Z = imm;
        }
        AUIPC { rd, imm } => {
            vm.rd = rd;
            vm.I = imm;
            vm.Z = add32(vm.pc, vm.I);
        }
        JAL { rd, imm } => {
            vm.rd = rd;
            vm.I = imm;
            vm.Z = add32(vm.pc, 4);
            vm.PC = add32(vm.pc, vm.I);
        }
        JALR { rd, rs1, imm } => {
            vm.rs1 = rs1;
            vm.rd = rd;
            vm.I = imm;
            vm.X = vm.get_reg(rs1);
            vm.Z = add32(vm.pc, 4);
            vm.PC = add32(vm.X, vm.I);
        }
        BR { bop, rs1, rs2, imm } => {
            vm.rs1 = rs1;
            vm.rs2 = rs2;
            vm.I = imm;
            vm.X = vm.get_reg(rs1);
            vm.Y = vm.get_reg(rs2);

            if br_op(bop, vm.X, vm.Y) {
                vm.PC = add32(vm.pc, imm);
            }
        }
        LOAD { lop, rd, rs1, imm } => {
            vm.rd = rd;
            vm.rs1 = rs1;
            vm.I = imm;
            vm.X = vm.get_reg(rs1);

            let addr = add32(vm.X, vm.I);
            match lop {
                LB => vm.Z = vm.mem.lb(addr),
                LH => vm.Z = vm.mem.lh(addr),
                LW => vm.Z = vm.mem.lw(addr),
                LBU => vm.Z = vm.mem.lbu(addr),
                LHU => vm.Z = vm.mem.lhu(addr),
            }
        }
        STORE { sop, rs1, rs2, imm } => {
            vm.rs1 = rs1;
            vm.rs2 = rs2;
            vm.I = imm;
            vm.X = vm.get_reg(rs1);
            vm.Y = vm.get_reg(rs2);

            let addr = add32(vm.X, vm.I);
            match sop {
                SB => vm.mem.sb(addr, vm.Y),
                SH => vm.mem.sh(addr, vm.Y),
                SW => vm.mem.sw(addr, vm.Y),
            }
        }
        ALUI { aop, rd, rs1, imm } => {
            vm.rs1 = rs1;
            vm.rd = rd;
            vm.I = imm;
            vm.X = vm.get_reg(rs1);
            vm.shamt = vm.I & 0x1f;
            vm.Z = alu_op(aop, vm.X, vm.I);
        }
        ALU { aop, rd, rs1, rs2 } => {
            vm.rs1 = rs1;
            vm.rs2 = rs2;
            vm.rd = rd;
            vm.X = vm.get_reg(rs1);
            vm.Y = vm.get_reg(rs2);
            vm.shamt = vm.Y & 0x1f;
            vm.Z = alu_op(aop, vm.X, vm.Y);
        }
        FENCE | EBREAK => {}
        ECALL => {
            let num = vm.regs[8]; // s0 = x8  syscall number
            let a0 = vm.regs[10]; // a0 = x10
            let a1 = vm.regs[11]; // a1 = x11

            // write_log
            if num == 1 {
                let mut stdout = std::io::stdout();
                for addr in a0..a0 + a1 {
                    let b = vm.mem.lb(addr) as u8;
                    stdout.write_all(&[b])?;
                }
                let _ = stdout.flush();
            } else {
                return Err(UnknownECall(vm.pc, num));
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
