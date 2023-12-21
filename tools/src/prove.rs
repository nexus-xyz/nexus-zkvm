use std::io::BufReader;
use std::fs::File;

use nexus_riscv::VMOpts;
use nexus_prover::{pp::gen_or_load, run, prove_par};
use nexus_network::pcd::{decode, NexusMsg::PCDRes};
use nexus_network::api::Proof;
use nexus_network::client::*;

use crate::*;

pub fn prove() -> CmdResult<()> {
    let Opts { command: Prove { release, bin } } = options() else {
        panic!()
    };
    let t = get_target(*release, bin)?;
    let proof = submit_proof("account".to_string(), &t)?;

    println!("{} submitted", proof.hash);

    Ok(())
}

pub fn query() -> CmdResult<()> {
    let Opts { command: Query { hash, file } } = options() else {
        panic!()
    };

    let proof = fetch_proof(hash)?;

    if proof.total_nodes > proof.complete_nodes {
        let pct = (proof.complete_nodes as f32) / (proof.total_nodes as f32);
        println!("{} {:.2}% complete", proof.hash, pct);
    } else {
        println!("{} 100% complete, saving...", proof.hash);
        let vec = serde_json::to_vec(&proof)?;
        write_file(file.clone(), &vec)?;
    }

    Ok(())
}

pub fn verify() -> CmdResult<()> {
    let Opts { command: Verify { pp_file, file } } = options() else {
        panic!()
    };

    let file = File::open(file)?;
    let reader = BufReader::new(file);
    let proof: Proof = serde_json::from_reader(reader)?;

    let Some(vec) = proof.proof else {
        return Err("invalid proof object".into());
    };

    let PCDRes(node) = decode(&vec)? else {
        return Err("invalid proof object".into());
    };

    let state = gen_or_load(false, 1, pp_file)?;

    match node.verify(&state) {
        Ok(_) => println!("{} verified", proof.hash),
        Err(_) => println!("{} NOT verified", proof.hash),
    }
    Ok(())
}

pub fn local() -> CmdResult<()> {
    let Opts {
        command: LocalProve { k, pp_file, release, bin },
    } = options()
    else {
        panic!()
    };
    let t = get_target(*release, bin)?;
    let opts = VMOpts {
        k: *k,
        nop: None,
        loopk: None,
        file: Some(t),
    };
    let trace = run(&opts, true)?;
    let state = gen_or_load(false, 1, pp_file)?;
    prove_par(state, trace)?;
    Ok(())
}
