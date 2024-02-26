//! A RISC-V virtual machine designed for verified computing

#![allow(non_snake_case)]

mod error;
pub mod machines;
pub mod rv32;
pub mod vm;

use clap::Args;
use elf::{abi::PT_LOAD, endian::LittleEndian, segment::ProgramHeader, ElfBytes};
use std::fs::read;
use std::path::PathBuf;

pub use error::*;
use rv32::*;
use vm::eval::*;

// don't break API
pub use machines::{loop_vm, nop_vm};

/// Load a VM state from an ELF file
pub fn load_elf(path: &PathBuf) -> Result<VM> {
    let file_data = read(path)?;
    let slice = file_data.as_slice();
    parse_elf(slice)
}

pub fn parse_elf(bytes: &[u8]) -> Result<VM> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes)?;

    let load_phdrs: Vec<ProgramHeader> = file
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .collect();

    let mut vm = VM::new(file.ehdr.e_entry as u32);

    for p in &load_phdrs {
        let s = p.p_offset as usize;
        let e = (p.p_offset + p.p_filesz) as usize;
        let bytes = &bytes[s..e];
        vm.init_memory(p.p_vaddr as u32, bytes)?;
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
    #[arg(group = "vm", short, long, name = "n")]
    pub nop: Option<usize>,

    /// Use a looping machine with l iterations
    #[arg(group = "vm", short, long, name = "l")]
    pub loopk: Option<usize>,

    /// Use a named test machine
    #[arg(group = "vm", long, long_help(list_machines()))]
    pub machine: Option<String>,

    /// Input file, RISC-V 32i ELF
    #[arg(group = "vm", required = true)]
    pub file: Option<std::path::PathBuf>,
}

fn list_machines() -> String {
    let ms = machines::MACHINES
        .iter()
        .map(|m| m.0.to_string())
        .collect::<Vec<String>>()
        .join(", ");
    "Use a named machine: ".to_string() + &ms
}

/// Load the VM described by `opts`
pub fn load_vm(opts: &VMOpts) -> Result<VM> {
    if let Some(k) = opts.nop {
        Ok(nop_vm(k))
    } else if let Some(k) = opts.loopk {
        Ok(loop_vm(k))
    } else if let Some(m) = &opts.machine {
        if let Some(vm) = machines::lookup_test_machine(m) {
            Ok(vm)
        } else {
            Err(VMError::UnknownMachine(m.clone()))
        }
    } else {
        load_elf(opts.file.as_ref().unwrap())
    }
}

/// Evaluate a program starting from a given machine state
pub fn eval(vm: &mut VM, show: bool) -> Result<()> {
    if show {
        println!("\nExecution:");
        println!(
            "{:7} {:8} {:32} {:>8} {:>8}",
            "pc", "mem[pc]", "inst", "Z", "PC"
        );
    }
    let t = std::time::Instant::now();
    let mut count = 0;

    loop {
        eval_inst(vm)?;
        count += 1;
        if show {
            println!("{:50} {:8x} {:8x}", vm.inst, vm.Z, vm.regs.pc);
        }
        if vm.inst.inst == RV32::UNIMP {
            break;
        }
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
        println!("\nFinal Machine State: pc: {:x}", vm.regs.pc);
        table("x", &vm.regs.x);

        println!("Executed {count} instructions in {:?}", t.elapsed());
    }
    Ok(())
}

/// Load and run an ELF file
pub fn run_vm(vm: &VMOpts, show: bool) -> Result<()> {
    let mut vm = load_vm(vm)?;
    eval(&mut vm, show)
}
