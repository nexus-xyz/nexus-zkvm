//! Evaluation for Nexus VM programs.

use num_traits::FromPrimitive;

use crate::error::{Result, NexusVMError::InvalidInstruction};
use crate::instructions::{Inst, Opcode, Opcode::*, Width};
use crate::memory::{Memory, path::Path};

/// State of a running Nexus VM program.
#[derive(Default)]
pub struct NexusVM {
    /// Current program counter.
    pub pc: u32,
    /// Register file.
    pub regs: [u32; 32],
    /// Most recent instruction.
    pub inst: Inst,
    /// Result of most recent instruction.
    pub Z: u32,
    /// Machine memory.
    pub memory: Memory,
    /// Merkle proof for current instruction at pc
    pub pc_path: Path,
    /// Merkle proof for load/store instructions.
    pub read_path: Option<Path>,
    /// Merkle proof for store instructions.
    pub write_path: Option<Path>,
}

/// Generate a trivial VM with a single HALT instruction.
pub fn halt_vm() -> NexusVM {
    let mut vm = NexusVM { pc: 0x1000, ..NexusVM::default() };
    let inst = Inst { opcode: HALT, ..Inst::default() };
    vm.memory.write_inst(vm.pc, inst.into()).unwrap();
    vm
}

#[inline]
fn add32(x: u32, y: u32) -> u32 {
    x.overflowing_add(y).0
}

#[inline]
fn sub32(x: u32, y: u32) -> u32 {
    x.overflowing_sub(y).0
}

// Evaluator for branch conditions.
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

/// Execute one step of a running Nexus VM.
/// This function will load the next instruction at the address
/// located at the program counter, execute the instruction,
/// and update the register file, program counter, and merkle
/// proofs.
pub fn eval_step(vm: &mut NexusVM) -> Result<()> {
    let (dword, path) = vm.memory.read_inst(vm.pc)?;
    let Some(inst) = Inst::from_u64(dword) else {
        return Err(InvalidInstruction(dword, vm.pc));
    };

    let I = inst.imm;
    let X = vm.regs[inst.rs1 as usize];
    let Y = vm.regs[inst.rs2 as usize];

    let YI = add32(Y, I);
    let shamt = YI & 0x1f;

    let mut PC = 0u32;

    vm.inst = inst;
    vm.Z = 0;
    vm.pc_path = path;
    vm.read_path = None;
    vm.write_path = None;

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
            vm.Z = add32(vm.pc, 8);
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
            vm.read_path = Some(path);
            vm.Z = val;
        }
        SB | SH | SW => {
            // Note: unwrap cannot fail
            let width = Width::try_from(inst.opcode).unwrap();
            let addr = add32(X, I);
            let (_, path) = vm.memory.load(width, addr)?;
            vm.read_path = Some(path);
            vm.write_path = Some(vm.memory.store(width, addr, Y)?);
        }

        ADD => vm.Z = add32(X, YI),
        SUB => vm.Z = sub32(X, YI),
        SLT => vm.Z = ((X as i32) < (YI as i32)) as u32,
        SLTU => vm.Z = (X < YI) as u32,
        SLL => vm.Z = X << shamt,
        SRL => vm.Z = X >> shamt,
        SRA => vm.Z = ((X as i32) >> shamt) as u32,
        AND => vm.Z = X & YI,
        OR => vm.Z = X | YI,
        XOR => vm.Z = X ^ YI,
    }

    if inst.rd > 0 {
        vm.regs[inst.rd as usize] = vm.Z;
    }

    if PC == 0 {
        vm.pc = add32(vm.pc, 8);
    } else {
        vm.pc = PC;
    }

    Ok(())
}

/// Run a VM to completion. The VM will stop when it encounters
/// a HALT instruction.
pub fn eval(vm: &mut NexusVM, verbose: bool) -> Result<()> {
    loop {
        let pc = vm.pc;
        eval_step(vm)?;
        if verbose {
            println!("{:x} {:?}", pc, vm.inst);
        }
        if vm.inst.opcode == HALT {
            break;
        }
    }
    Ok(())
}
