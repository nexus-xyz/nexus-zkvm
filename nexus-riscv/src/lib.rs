//! A RISC-V virtual machine designed for verified computing

#![allow(non_snake_case)]

mod error;
pub mod rv32;
pub mod vm;

pub use error::*;
use rv32::*;
use vm::*;

use elf::{abi::PT_LOAD, endian::LittleEndian, segment::ProgramHeader, ElfBytes};
use std::fs::read;
use std::path::PathBuf;

/// Load a VM state from an ELF file
pub fn load_elf(path: &PathBuf) -> Result<VM> {
    let file_data = read(path)?;
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice)?;

    let load_phdrs: Vec<ProgramHeader> = file
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .collect();

    let mut vm = VM::default();
    vm.pc = 0x1000; // TODO

    for p in &load_phdrs {
        let s = p.p_offset as usize;
        let e = (p.p_offset + p.p_filesz) as usize;
        let bytes = &slice[s..e];
        vm.init_memory(p.p_vaddr as u32, bytes);
    }

    Ok(vm)
}

/// Evaluate a program starting from a given machine state
pub fn eval(vm: &mut VM, show: bool) -> Result<()> {
    if show {
        println!("\nExecution:");
        println!(
            "{:7} {:8} {:32} {:>8} {:>8} {:>8} {:>8} {:>8}",
            "pc", "mem[pc]", "inst", "X", "Y", "I", "Z", "PC"
        );
    }

    loop {
        eval_inst(vm)?;
        if show {
            println!(
                "{:50} {:8x} {:8x} {:8x} {:8x} {:8x}",
                vm.inst, vm.X, vm.Y, vm.I, vm.Z, vm.PC
            );
        }
        if vm.inst.inst == RV32::UNIMP {
            break;
        }
        eval_writeback(vm);
    }

    fn table(name: &str, mem: &[u32]) {
        for (i, w) in mem.iter().enumerate() {
            print!("  {}{:02}: {:8x}", name, i, w);
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
    Ok(())
}

/// Load and run an ELF file
pub fn run_elf(file: &PathBuf, trace: bool) -> Result<()> {
    let mut vm = load_elf(file)?;
    eval(&mut vm, trace)?;
    Ok(())
}
