//! A RISC-V virtual machine designed for verified computing

#![allow(non_snake_case)]
#![allow(clippy::field_reassign_with_default)]

pub mod error;
pub mod eval;
pub mod machines;
pub mod rv32;

pub mod syscalls;
pub mod trace;

mod ark_serde;
pub mod memory;

pub mod circuit;

use clap::Args;
use elf::{abi::PT_LOAD, endian::LittleEndian, ElfBytes};
use std::fs::read;
use std::path::PathBuf;
use std::time::Instant;

pub use error::*;
use eval::*;
use memory::*;
use rv32::*;
use trace::*;

// don't break API
pub use machines::{loop_vm, nop_vm};

// re-export
#[doc(hidden)]
pub use elf;

/// Load a VM state from an ELF file
pub fn load_elf<M: Memory>(path: &PathBuf) -> Result<NexusVM<M>> {
    let file_data = read(path)?;
    let slice = file_data.as_slice();
    parse_elf(slice)
}

#[doc(hidden)]
pub fn parse_elf_bytes(bytes: &[u8]) -> Result<ElfBytes<LittleEndian>> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes)?;
    Ok(file)
}

#[doc(hidden)]
pub fn init_vm<M: Memory>(elf: &ElfBytes<LittleEndian>, data: &[u8]) -> Result<NexusVM<M>> {
    let e_entry = elf.ehdr.e_entry as u32;

    let load_phdrs = elf
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD);

    let mut vm = NexusVM::new(e_entry);
    for p in load_phdrs {
        let s = p.p_offset as usize;
        let e = (p.p_offset + p.p_filesz) as usize;
        let bytes = &data[s..e];
        vm.init_memory(p.p_vaddr as u32, bytes)?;
    }
    Ok(vm)
}

pub fn parse_elf<M: Memory>(bytes: &[u8]) -> Result<NexusVM<M>> {
    let file = parse_elf_bytes(bytes)?;
    init_vm(&file, bytes)
}

/// A structure describing a VM to load.
/// This structure can be used with clap.
#[derive(Default, Debug, Args)]
pub struct VMOpts {
    /// Instructions per step
    #[arg(short, name = "k", default_value = "1")]
    pub k: usize,

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
pub fn load_vm<M: Memory>(opts: &VMOpts) -> Result<NexusVM<M>> {
    if let Some(m) = &opts.machine {
        if let Some(vm) = machines::lookup_test_machine(m) {
            Ok(vm)
        } else {
            Err(NexusVMError::UnknownMachine(m.clone()))
        }
    } else {
        load_elf(opts.file.as_ref().unwrap())
    }
}

/// Evaluate a program starting from a given machine state
pub fn eval(vm: &mut NexusVM<impl Memory>, show: bool, verbose: bool) -> Result<()> {
    if show {
        vm.enable_stdout();
    }

    if verbose {
        println!("\nExecution:");
        println!(
            "{:7} {:8} {:32} {:>8} {:>8}",
            "pc", "mem[pc]", "inst", "Z", "PC"
        );
    }
    let t = std::time::Instant::now();

    loop {
        eval_inst(vm)?;
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

        println!(
            "Executed {} instructions in {:?}",
            vm.trace_len,
            t.elapsed()
        );
    }
    Ok(())
}

/// Load and run an ELF file
pub fn run_vm<M: Memory>(vm: &VMOpts, show: bool) -> Result<()> {
    let mut vm: NexusVM<M> = load_vm(vm)?;
    eval(&mut vm, show)
}

/// Load and run an ELF file, then return the execution trace
pub fn trace_vm<M: Memory>(
    opts: &VMOpts,
    pow: bool,
    show: bool,
    verbose: bool.
) -> Result<Trace<M::Proof>, NexusVMError> {
    let mut vm = load_vm::<M>(opts)?;

    if show {
        vm.enable_stdout();
    }

    if verbose {
        println!("Executing program...");
    }

    let start = Instant::now();
    let trace = trace::<M>(&mut vm, opts.k, pow)?;

    if verbose {
        println!(
            "Executed {} instructions in {:?}. {} bytes used by trace.",
            trace.k * trace.blocks.len(),
            start.elapsed(),
            &trace.estimate_size(),
        );
    }

    Ok(trace)
}
