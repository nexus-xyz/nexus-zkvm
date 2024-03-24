//! Evaluation for Nexus VM programs.

use num_traits::FromPrimitive;

use crate::error::{NexusVMError::InvalidInstruction, Result};
use crate::instructions::{Inst, Opcode, Opcode::*, Width};
use crate::memory::Memory;
use crate::syscalls::Syscalls;

/// State of a running Nexus VM program.
#[derive(Default)]
pub struct NexusVM<M: Memory> {
    /// Current program counter.
    pub pc: u32,
    /// Register file.
    pub regs: [u32; 32],
    /// Most recent instruction.
    pub inst: Inst,
    /// Result of most recent instruction.
    pub Z: u32,
    /// Syscall implementation
    pub syscalls: Syscalls,
    /// Machine memory.
    pub memory: M,
    /// Memory proof for current instruction at pc
    pub pc_proof: M::Proof,
    /// Memory proof for load/store instructions.
    pub read_proof: Option<M::Proof>,
    /// Memory proof for store instructions.
    pub write_proof: Option<M::Proof>,
}

/// Generate a trivial VM with a single NOP and a single HALT instruction.
pub fn halt_vm<M: Memory>() -> NexusVM<M> {
    let mut vm = NexusVM::<M>::default();
    let inst = Inst { opcode: NOP, ..Inst::default() };
    vm.memory.write_inst(vm.pc, inst.into()).unwrap();
    let inst = Inst { opcode: HALT, ..Inst::default() };
    vm.memory.write_inst(vm.pc + 8, inst.into()).unwrap();
    vm
}

#[inline]
fn add32(x: u32, y: u32) -> u32 {
    x.overflowing_add(y).0
}

#[inline]
fn mul32(x: u32, y: u32) -> u32 {
    x.overflowing_mul(y).0
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
pub fn eval_step(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    let (dword, proof) = vm.memory.read_inst(vm.pc)?;
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
    vm.pc_proof = proof;
    vm.read_proof = None;
    vm.write_proof = None;

    match inst.opcode {
        NOP => {}
        HALT => {
            PC = vm.pc;
        }
        SYS => vm.syscalls.syscall(vm.pc, vm.regs, &vm.memory)?,

        JAL => {
            vm.Z = add32(vm.pc, 8);
            let XI = add32(X, I);
            // This semantics treats canonical call/ret
            // differently from general jalr.
            // TODO: seperate call/ret into their own instructions.
            if inst.rs1 <= 1 {
                PC = XI;
            } else {
                PC = mul32(XI, 2);
            }
        }
        BEQ | BNE | BLT | BGE | BLTU | BGEU => {
            if brcc(inst.opcode, X, Y) {
                PC = add32(vm.pc, I);
            }
        }

        LB | LH | LW | LBU | LHU => {
            // Note: unwrap cannot fail
            let width = Width::try_from(inst.opcode).unwrap();
            let addr = add32(X, I);
            let (val, proof) = vm.memory.load(width, addr)?;
            vm.read_proof = Some(proof);
            vm.Z = val;
        }
        SB | SH | SW => {
            // Note: unwrap cannot fail
            let width = Width::try_from(inst.opcode).unwrap();
            let addr = add32(X, I);
            let (_, proof) = vm.memory.load(width, addr)?;
            vm.read_proof = Some(proof);
            vm.write_proof = Some(vm.memory.store(width, addr, Y)?);
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
pub fn eval(vm: &mut NexusVM<impl Memory>, verbose: bool) -> Result<()> {
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
