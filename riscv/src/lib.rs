//! A RISC-V virtual machine designed for verified computing

#![allow(non_snake_case)]

mod error;
pub mod rv32;
pub mod vm;

pub use error::*;
use rv32::*;
use vm::*;

use clap::Args;
use elf::{abi::PT_LOAD, endian::LittleEndian, segment::ProgramHeader, ElfBytes};
use std::fs::read;
use std::path::PathBuf;

/// Create a VM with k no-op instructions
pub fn nop_vm(k: usize) -> VM {
    let mut pc = 0x1000;
    let mut vm = VM { pc, ..VM::default() };
    // TODO: we can do better for large k
    for _ in 0..k {
        vm.mem.sw(pc, 0x00000013); // nop
        pc += 4;
    }
    vm.mem.sw(pc, 0xc0001073); // unimp
    vm
}

/// Create a VM which loops k times
pub fn loop_vm(k: usize) -> VM {
    assert!(k < (1 << 31));

    let mut vm = VM { pc: 0x1000, ..VM::default() };

    let hi = (k as u32) & 0xfffff000;
    let lo = ((k & 0xfff) << 20) as u32;
    vm.mem.sw(0x1000, hi | 0x137); // lui x2, hi
    vm.mem.sw(0x1004, lo | 0x10113); // addi x2, x2, lo
    vm.mem.sw(0x1008, 0x00000093); // li x1, 0
    vm.mem.sw(0x100c, 0x00108093); // addi x1, x1, 1
    vm.mem.sw(0x1010, 0xfe209ee3); // bne x1, x2, 0x100c
    vm.mem.sw(0x1014, 0xc0001073); // unimp
    vm
}

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

    // TODO: read PC from elf file (and related changes)
    let mut vm = VM { pc: 0x1000, ..VM::default() };

    for p in &load_phdrs {
        let s = p.p_offset as usize;
        let e = (p.p_offset + p.p_filesz) as usize;
        let bytes = &slice[s..e];
        vm.init_memory(p.p_vaddr as u32, bytes);
    }

    Ok(vm)
}

/// A structure describing a VM to load.
/// This structure can be used with clap.
#[derive(Debug, Args)]
pub struct VMOpts {
    /// Instructions per step
    #[arg(short, name = "k", default_value = "1")]
    pub k: usize,

    /// Use a no-op machine of size n
    #[arg(group = "vm", short, name = "n")]
    pub nop: Option<usize>,

    /// Use a looping machine with l iterations
    #[arg(group = "vm", short, name = "l")]
    pub loopk: Option<usize>,

    /// Input file, RISC-V 32i ELF
    #[arg(group = "vm", required = true)]
    pub file: Option<std::path::PathBuf>,
}

/// Load the VM described by `opts`
pub fn load_vm(opts: &VMOpts) -> Result<VM> {
    if let Some(k) = opts.nop {
        Ok(nop_vm(k))
    } else if let Some(k) = opts.loopk {
        Ok(loop_vm(k))
    } else {
        load_elf(opts.file.as_ref().unwrap())
    }
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
pub fn run_vm(vm: &VMOpts, trace: bool) -> Result<()> {
    let mut vm = load_vm(vm)?;
    eval(&mut vm, trace)
}
