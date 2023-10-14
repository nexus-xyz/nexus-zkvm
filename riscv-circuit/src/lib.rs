#![allow(non_snake_case)]

//! Circuits for the Nexus RISC-V virtual machine

pub mod r1cs;
pub mod riscv;

use r1cs::*;
use riscv::*;

use nexus_riscv::{Result, nop_vm, rv32::*, vm::*};

pub struct Trace {
    pub k: usize,
    pub cs: R1CS,
    pub trace: Vec<V>,
}

pub fn step_circuit(k: usize) -> Result<Trace> {
    // use unimp instruction as nop
    let mut vm = nop_vm(0);
    eval_inst(&mut vm)?;

    let cs = big_step(&vm, false);

    let tr = Trace { k, cs, trace: Vec::new() };
    Ok(tr)
}

pub fn step(tr: &mut Trace, vm: &mut VM, check: bool) -> Result<bool> {
    // Note: the VM will loop on the final unimp instruction,
    // so we can just assume we will have enough.

    for _ in 0..tr.k {
        eval_inst(vm)?;
        let cs = big_step(vm, true);
        eval_writeback(vm);

        if check {
            let mut chk = tr.cs.clone();
            chk.w = cs.w.clone();
            assert!(chk.is_sat());
        }

        tr.trace.push(cs.w);
    }
    Ok(vm.inst.inst == RV32::UNIMP)
}

pub fn eval(vm: &mut VM, k: usize, check: bool) -> Result<Trace> {
    let mut trace = step_circuit(k)?;
    loop {
        if step(&mut trace, vm, check)? {
            break;
        }
    }
    Ok(trace)
}
