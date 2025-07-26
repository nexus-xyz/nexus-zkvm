use nexus_vm::elf::ElfFile;
use nexus_vm::emulator::{Emulator, HarvardEmulator};
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: nexus-vm-runner <path-to-elf>");
        std::process::exit(1);
    }

    let elf_path = &args[1];
    let elf_bytes = fs::read(elf_path).expect("Failed to read ELF file");

    let elf_file = ElfFile::from_bytes(&elf_bytes).expect("Failed to parse ELF");
    let mut emulator = HarvardEmulator::from_elf(&elf_file, &[], &[]);

    match emulator.execute(true) {
        Ok(_) => {
            println!("Execution finished successfully.");
        }
        Err(e) => {
            eprintln!("Execution failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
