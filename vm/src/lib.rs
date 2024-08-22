//! A RISC-V virtual machine designed for verified computing

#![allow(non_snake_case)]
#![allow(clippy::field_reassign_with_default)]

pub mod error;
pub mod eval;
pub mod rv32;

pub mod trace;

pub mod memory;

use elf::{abi::PT_LOAD, endian::LittleEndian, ElfBytes};
use std::fs::read;
use std::path::PathBuf;
use std::time::Instant;

pub use error::*;
use eval::*;
use memory::*;
use rv32::*;
use trace::*;

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

/// Evaluate a program starting from a given machine state
pub fn eval(vm: &mut NexusVM<impl Memory>) -> Result<()> {
    let _t = std::time::Instant::now();

    loop {
        eval_inst(vm)?;
        if vm.inst.inst == RV32::UNIMP {
            break;
        }
    }

    #[allow(dead_code)]
    fn table(name: &str, mem: &[u32]) {
        for (i, w) in mem.iter().enumerate() {
            print!("  {}{:02}: {:8x}", name, i, w);
            if (i % 8) == 7 {
                println!();
            }
        }
        println!();
    }

    Ok(())
}

/// Load and run an ELF file, then return the execution trace
pub fn trace_vm<M: Memory>(
    vm: &mut NexusVM<M>,
    k: usize,
    pow: bool,
) -> Result<Trace, NexusVMError> {
    let _start = Instant::now();
    let trace = trace(vm, k, pow)?;

    Ok(trace)
}
