use std::fs::File;

use nexus_riscv::vm::VM;
use nexus_riscv_circuit::{
    Trace,
    eval,
};

use crate::types::*;
use crate::error::*;
use crate::circuit::Tr;

pub fn gen_pp<T>(circuit: &T) -> Result<PP<T>, SynthesisError>
    where T: StepCircuit<F1>,
{
    let (ark, mds) = find_poseidon_ark_and_mds::<F1>(
        F1::MODULUS_BIT_SIZE as u64,
        2,
        8,
        43,
        0,
    );
    let ro_config = PoseidonConfig {
        full_rounds: 8,
        partial_rounds: 43,
        alpha: 5,
        ark,
        mds,
        rate: 2,
        capacity: 1,
    };
    PP::setup(ro_config, circuit)
}

pub fn show_pp<T>(pp: &PP<T>) {
    let PublicParams {
        ro_config,
        shape,
        shape_ec,
        pp,
        pp_ec,
        digest,
        ..
    } = pp;

    println!("Poseidon ark: {} mds: {}", ro_config.ark.len(), ro_config.mds.len());
    println!("shape  {} x {}", shape.num_constraints, shape.num_vars);
    println!("shape_ec {} x {}", shape_ec.num_constraints, shape_ec.num_vars);
    println!("pp {}", pp.len());
    println!("pp_ec {}", pp_ec.len());
    println!("digest {:?}", digest);
}

pub fn save_pp<T>(pp: PP<T>, file: &str) -> Result<(), ProofError> {
    let PublicParams {
        ro_config,
        shape,
        shape_ec,
        pp,
        pp_ec,
        digest,
        ..
    } = pp;

    let ppd = PPDisk {
        ro_config: ro_config,
        circuit1: shape,
        circuit2: shape_ec,
        pp1: pp,
        pp2: pp_ec,
        digest: digest,
    };

    let f = File::create(file)?;
    ppd.serialize_compressed(&f)?;
    f.sync_all()?;
    Ok(())
}

pub fn load_pp<T>(file: &str) -> Result<PP<T>, ProofError> {
    let f = File::open(file)?;
    let ppd: PPDisk = PPDisk::deserialize_compressed(&f)?;

    Ok(PublicParams {
        ro_config: ppd.ro_config,
        shape: ppd.circuit1,
        shape_ec: ppd.circuit2,
        pp: ppd.pp1,
        pp_ec: ppd.pp2,
        digest: ppd.digest,
        _step_circuit: PhantomData,
    })
}

// -- VM specific versions

fn nop_trace() -> Result<Trace, VMError> {
    let mut vm = VM::default();
    vm.pc = 0x1000;
    vm.init_memory(0x1000, &[
        0x13, 0x00, 0x00, 0x00, // nop
        0x73, 0x10, 0x00, 0xC0, // unimp
    ]);
    eval(&mut vm, false, false)
}

pub fn gen_vm_pp() -> Result<PP<Tr>, ProofError> {
    let tr = Tr::new(nop_trace()?);
    let pp = gen_pp(&tr)?;
    Ok(pp)
}
