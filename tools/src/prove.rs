use std::io::BufReader;
use std::fs::File;

use nexus_prover::types::com::PVC;
use nexus_prover::Proof;
use nexus_prover::types::{PublicParams, C2, G1, G2, PC, RO, SC, SRS};
use nexus_riscv::VMOpts;
use nexus_prover::{pp::gen_or_load, run, prove_par, srs::test_srs::gen_test_srs_to_file};
use nexus_network::pcd::{decode, NexusMsg::PCDRes};
use nexus_network::client::*;
use supernova::circuits::nova::pcd::compression::SNARK;
use supernova::nova::pcd::PCDNode;

use crate::*;
use ark_serialize::CanonicalDeserialize;

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
    let Opts { command: Verify { pp_file, file, local } } = options() else {
        panic!()
    };

    let file = File::open(file)?;
    let reader = BufReader::new(file);
    let proof: Proof = serde_json::from_reader(reader)?;

    let Some(vec) = proof.proof else {
        return Err("invalid proof object".into());
    };

    let node;

    if *local {
        println!("doing local verify");
        let tmp = nexus_prover::types::PCDNode::deserialize_compressed(&*vec);
        match tmp {
            Ok(n) => node = n,
            Err(_) => return Err("invalid proof object".into()),
        };
    } else {
        let tmp = decode(&vec)?;
        match tmp {
            PCDRes(n) => node = n,
            _ => return Err("invalid proof object".into()),
        };
    };

    let state = gen_or_load(false, 1, pp_file, &())?;

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
        merkle: true,
        nop: None,
        loopk: None,
        machine: None,
        file: Some(t),
    };
    let trace = run(&opts, true)?;
    let state = gen_or_load(false, 1, pp_file, &())?;
    let proof = prove_par(state, trace)?;

    let vec = serde_json::to_vec(&proof)?;
    write_file("local-proof.json".into(), &vec)?;

    Ok(())
}

pub fn sample_test_srs() -> CmdResult<()> {
    let Opts {
        command: SampleTestSRS { num_vars, file },
    } = options()
    else {
        panic!()
    };

    gen_test_srs_to_file(*num_vars, file)?;
    Ok(())
}
