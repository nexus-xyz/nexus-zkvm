#![allow(non_snake_case)]

//! Circuits for the Nexus RISC-V virtual machine

pub mod q;
pub mod r1cs;
pub mod riscv;

use r1cs::*;
use riscv::*;

use nexus_riscv::{Result, nop_vm, rv32::*, vm::*};

use std::ops::Range;

#[derive(Default)]
pub struct Trace {
    pub k: usize,
    pub input: Range<usize>,
    pub output: Range<usize>,
    pub cs: R1CS,
    pub code: Vec<Inst>, // this is just for nice output
    pub trace: Vec<V>,
}

pub fn k_step_circuit(k: usize) -> Result<Trace> {
    debug_assert!(k > 0);

    // use unimp instruction as nop
    let mut vm = nop_vm(0);
    eval_inst(&mut vm)?;

    let cs = big_step(&vm, false);

    // see riscv::init_cs
    let tr = Trace {
        k,
        input: Range { start: 1, end: 34 },
        output: Range { start: 34, end: 67 },
        cs,
        ..Trace::default()
    };
    Ok(tr)
}

// Execute k steps, return false if this is the last set of instructions.
pub fn k_step(tr: &mut Trace, vm: &mut VM, show: bool, check: bool) -> Result<bool> {
    // Note: the VM will loop on the final unimp instruction,
    // so we can just assume we will have enough.
    for _ in 0..tr.k {
        eval_inst(vm)?;

        if show {
            #[rustfmt::skip]
            println!(
                "{:50} {:8x} {:8x} {:8x} {:8x} {:8x}",
                vm.inst, vm.X, vm.Y, vm.I, vm.Z, vm.PC
            );
        }

        let cs = big_step(vm, true);
        eval_writeback(vm);

        if check {
            let mut chk = tr.cs.clone();
            chk.w = cs.w.clone();
            assert!(chk.is_sat());
        }

        tr.code.push(vm.inst);
        tr.trace.push(cs.w);
    }
    Ok(vm.inst.inst == RV32::UNIMP)
}

pub fn eval(vm: &mut VM, k: usize, show: bool, check: bool) -> Result<Trace> {
    if show {
        println!("\nExecution:");
        #[rustfmt::skip]
        println!(
            "{:7} {:8} {:32} {:>8} {:>8} {:>8} {:>8} {:>8}",
            "pc", "mem[pc]", "inst", "X", "Y", "I", "Z", "PC"
        );
    }

    let mut trace = k_step_circuit(k)?;
    loop {
        if k_step(&mut trace, vm, show, check)? {
            break;
        }
    }

    fn table(name: &str, mem: &[u32]) {
        for (i, x) in mem.iter().enumerate() {
            print!("  {}{:02}: {:8x}", name, i, x);
            if (i % 8) == 7 {
                println!();
            }
        }
        println!();
    }

    if show {
        println!("\nFinal Machine State: pc: {:x}", vm.pc);
        table("x", &vm.regs);
    }
    Ok(trace)
}
