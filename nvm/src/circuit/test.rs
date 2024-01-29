use crate::{
    error::Result,
    riscv::test::test_machines,
    eval::{NVM, halt_vm},
    trace::trace,
};

use super::{r1cs::R1CS, nvm::step};

// generate R1CS matrices
fn vm_circuit(k: usize) -> Result<R1CS> {
    let mut vm = halt_vm();
    let tr = trace(&mut vm, k, false)?;
    let w = tr.blocks[0].into_iter().next().unwrap();
    Ok(step(&w, false))
}

// check each step of each block for satisfiability
fn nvm_check(circuit: &mut R1CS, mut vm: NVM, k: usize) -> Result<()> {
    let tr = trace(&mut vm, k, false)?;
    for b in &tr.blocks {
        for w in b {
            let cs = step(&w, true);
            circuit.w = cs.w;
            assert!(circuit.is_sat());
        }
    }
    Ok(())
}

#[test]
#[ignore]
fn nvm_step() {
    let mut circuit = vm_circuit(1).unwrap();
    let vm = halt_vm();
    nvm_check(&mut circuit, vm, 1).unwrap();

    for (name, vm) in test_machines() {
        println!("Checking {name}");
        let t = std::time::Instant::now();
        nvm_check(&mut circuit, vm, 1).unwrap();
        println!("{:?}", t.elapsed());
    }
}
