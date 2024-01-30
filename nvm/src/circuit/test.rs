use ark_relations::r1cs::ConstraintSystem;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::{FpVar},
};

use crate::{
    error::Result,
    riscv::test::test_machines,
    eval::{NVM, halt_vm},
    trace::trace,
};

use super::{F, r1cs::R1CS, nvm::step, step::build_constraints};

// generate R1CS matrices
fn vm_circuit(k: usize) -> Result<R1CS> {
    let mut vm = halt_vm();
    let tr = trace(&mut vm, k, false)?;
    let w = tr.blocks[0].into_iter().next().unwrap();
    Ok(step(&w, false))
}

// check each step of each block for satisfiability
// all values of k are equivalent at this level
fn nvm_check_steps(mut vm: NVM) -> Result<()> {
    let mut rcs = vm_circuit(1)?;
    assert!(rcs.is_sat());

    let tr = trace(&mut vm, 1, false)?;
    for b in &tr.blocks {
        for w in b {
            let cs = step(&w, true);
            rcs.w = cs.w;
            assert!(rcs.is_sat());
        }
    }
    Ok(())
}

#[test]
#[ignore]
fn nvm_step() {
    let vm = halt_vm();
    nvm_check_steps(vm).unwrap();

    for (name, vm) in test_machines() {
        println!("Checking {name}");
        nvm_check_steps(vm).unwrap();
    }
}

fn ark_check(mut vm: NVM, k: usize) -> Result<()> {
    let tr = trace(&mut vm, k, false)?;

    for i in 0..tr.blocks.len() {
        let cs = ConstraintSystem::<F>::new_ref();
        let inp = tr
            .input(i)
            .unwrap()
            .iter()
            .map(|f| FpVar::new_input(cs.clone(), || Ok(f)).unwrap())
            .collect::<Vec<_>>();

        build_constraints(cs.clone(), i, &inp, &tr).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    Ok(())
}

fn ark_check_steps(k: usize) {
    let vm = halt_vm();
    ark_check(vm, k).unwrap();

    for (name, vm) in test_machines() {
        println!("Checking {name}");
        ark_check(vm, k).unwrap();
    }
}

#[test]
#[ignore]
fn ark_step() {
    for k in [1, 4, 13] {
        println!("k={k}");
        ark_check_steps(k);
    }
}
