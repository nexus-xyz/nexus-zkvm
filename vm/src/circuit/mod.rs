#![allow(non_snake_case)]

//! Circuits for the Nexus RISC-V virtual machine

pub mod r1cs;
pub mod riscv;

pub use r1cs::*;
pub use riscv::*;

use crate::{eval::*, nop_vm, trace::*, memory::MemoryProof, Result};

pub use crate::trace::Trace;

pub fn step_circuit() -> Result<R1CS> {
    // use unimp instruction as nop
    let mut vm = nop_vm(0);
    let mut tr = trace(&mut vm, 1, false)?;
    let b0 = tr.blocks.remove(0);
    let w = b0.into_iter().next().unwrap();
    let cs = big_step(&w, false);
    Ok(cs)
}

pub fn eval<P: MemoryProof>(vm: &mut VM, k: usize, check: bool) -> Result<Trace<P>> {
    let tr = trace(vm, k, false)?;
    if check {
        let mut cs = step_circuit()?;
        for b in &tr.blocks {
            println!("checking block...");
            for w in b {
                println!("checking step...");
                let cs2 = big_step(&w, false);
                cs.w = cs2.w;
                assert!(cs.is_sat());
            }
        }
    }
    Ok(tr)
}
