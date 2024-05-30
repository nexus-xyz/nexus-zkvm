use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;

use crate::{
    error::Result,
    eval::NexusVM,
    machines::loop_vm,
    memory::{trie::MerkleTrie, Memory},
    trace::trace,
};

use super::{r1cs::R1CS, riscv::step, step::build_constraints, F};

// generate R1CS matrices
fn vm_circuit(k: usize) -> Result<R1CS> {
    let mut vm = loop_vm::<MerkleTrie>(5);
    let tr = trace(&mut vm, k, false)?;
    let w = tr.blocks[0].into_iter().next().unwrap();
    Ok(step(&w, false))
}

// check each step of each block for satisfiability
// all values of k are equivalent at this level
fn nvm_check_steps(mut vm: NexusVM<impl Memory>) -> Result<()> {
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
    let vm = loop_vm::<MerkleTrie>(5);
    nvm_check_steps(vm).unwrap();
}

fn ark_check(mut vm: NexusVM<impl Memory>, k: usize) -> Result<()> {
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
    let vm = loop_vm::<MerkleTrie>(5);
    ark_check(vm, k).unwrap();
}

#[test]
#[ignore]
fn ark_step() {
    for k in [1, 4, 13] {
        println!("k={k}");
        ark_check_steps(k);
    }
}
