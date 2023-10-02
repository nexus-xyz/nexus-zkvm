#![allow(non_snake_case)]

//! Circuits for the Nexus RISC-V virtual machine

pub mod q;
pub mod r1cs;
pub mod riscv;

use r1cs::*;
use riscv::*;

use nexus_riscv::Result;
use nexus_riscv::rv32::*;
use nexus_riscv::vm::*;

pub struct Trace {
    pub cs: R1CS,
    pub code: Vec<Inst>, // this is just for nice output
    pub trace: Vec<V>,
}

pub fn eval(vm: &mut VM, show: bool, check: bool) -> Result<Trace> {
    if show {
        println!("\nExecution:");
        #[rustfmt::skip]
        println!(
            "{:7} {:8} {:32} {:>8} {:>8} {:>8} {:>8} {:>8}",
            "pc", "mem[pc]", "inst", "X", "Y", "I", "Z", "PC"
        );
    }

    let mut trace = Trace {
        cs: R1CS::default(),
        code: Vec::new(),
        trace: Vec::new(),
    };

    loop {
        eval_inst(vm)?;
        if show {
            #[rustfmt::skip]
            println!(
                "{:50} {:8x} {:8x} {:8x} {:8x} {:8x}",
                vm.inst, vm.X, vm.Y, vm.I, vm.Z, vm.PC
            );
        }
        if vm.inst.inst == RV32::UNIMP {
            break;
        }

        let cs = big_step(vm, !trace.trace.is_empty());

        trace.code.push(vm.inst);

        if !cs.witness_only {
            trace.cs = cs;
            trace.trace.push(trace.cs.w.clone());
        } else {
            if check {
                // for debugging
                trace.cs.w = cs.w.clone();
            }
            trace.trace.push(cs.w);
        }
        // debugging
        if check {
            assert!(trace.cs.is_sat());
        }
        eval_writeback(vm);
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
