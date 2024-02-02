use crate::error::Result;
use crate::instructions::{Inst, Opcode, Opcode::*, Width};
use crate::memory::{Memory, path::Path};

pub struct NVM {
    pub pc: u32,
    pub regs: [u32; 32],
    pub memory: Memory,
    pub pc_path: Path,
    pub read_path: Path,
    pub write_path: Path,
}

#[inline]
fn add32(x: u32, y: u32) -> u32 {
    x.overflowing_add(y).0
}

#[inline]
fn sub32(x: u32, y: u32) -> u32 {
    x.overflowing_sub(y).0
}

fn brcc(opcode: Opcode, x: u32, y: u32) -> bool {
    match opcode {
        BEQ => x == y,
        BNE => x != y,
        BLT => (x as i32) < (y as i32),
        BGE => (x as i32) >= (y as i32),
        BLTU => x < y,
        BGEU => x >= y,
        _ => unreachable!(),
    }
}

pub fn step(vm: &mut NVM) -> Result<()> {
    let inst = Inst::default();

    let I = inst.imm;
    let X = vm.regs[inst.rs1 as usize];
    let Y = vm.regs[inst.rs2 as usize];

    let YI = add32(Y, I);
    let shamt = YI & 0x1f;

    let mut Z = 0u32;
    let mut PC = 0u32;

    match inst.opcode {
        NOP => {}
        HALT => {
            PC = vm.pc;
        }
        SYS => {
            let num = vm.regs[18]; // s2 = x18  syscall number
            let a0 = vm.regs[10]; // a0 = x10
            let a1 = vm.regs[11]; // a1 = x11
            println!("SYS CALL {num} {a0:x} {a1:x}");
        }

        JAL => {
            Z = add32(vm.pc, 8);
            PC = add32(X, I);
        }
        BEQ | BNE | BLT | BGE | BLTU | BGEU => {
            if brcc(inst.opcode, X, Y) {
                PC = add32(vm.pc, I)
            }
        }

        LB | LH | LW | LBU | LHU => {
            // Note: unwrap cannot fail
            let width = Width::try_from(inst.opcode).unwrap();
            let addr = add32(X, I);
            let (val, path) = vm.memory.load(width, addr)?;
            vm.read_path = path;
            Z = val;
        }
        SB | SH | SW => {
            // Note: unwrap cannot fail
            let width = Width::try_from(inst.opcode).unwrap();
            let addr = add32(X, I);
            let (_, path) = vm.memory.load(width, addr)?;
            vm.read_path = path;
            vm.write_path = vm.memory.store(width, addr, Y)?;
        }

        ADD => Z = add32(X, YI),
        SUB => Z = sub32(X, YI),
        SLT => Z = ((X as i32) < (YI as i32)) as u32,
        SLTU => Z = (X < Y) as u32,
        SLL => Z = X << shamt,
        SRL => Z = X >> shamt,
        SRA => Z = ((X as i32) >> shamt) as u32,
        AND => Z = X & YI,
        OR => Z = X | YI,
        XOR => Z = X ^ YI,
    }

    if inst.rd > 0 {
        vm.regs[inst.rd as usize] = Z;
    }

    if PC == 0 {
        vm.pc = add32(PC, 8);
    } else {
        vm.pc = PC;
    }

    Ok(())
}
