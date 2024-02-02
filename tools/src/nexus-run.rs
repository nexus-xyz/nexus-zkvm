use nexus_riscv::*;
use std::env;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage nexus-run <elf_file>");
        process::exit(1);
    }

    let opts = VMOpts {
        k: 1,
        nop: None,
        loopk: None,
        machine: None,
        file: Some(PathBuf::from(args[1].clone())),
    };
    match run_vm(&opts, false) {
        Ok(()) => (),
        Err(e) => {
            println!("{e}");
            process::exit(1)
        }
    }
}
