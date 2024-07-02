use crate::traits::*;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use nexus_core::nvm::NexusVM;
use nexus_core::nvm::interactive::{load_elf, parse_elf, trace, eval};
use nexus_core::nvm::memory::MerkleTrie;
use nexus_core::prover::nova::types::{SeqPP, IVCProof};
use nexus_core::prover::nova::error::ProofError;
use nexus_core::prover::nova::pp::{gen_vm_pp, load_pp, save_pp};
use nexus_core::prover::nova::prove_seq;

use std::marker::PhantomData;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 64;

pub struct Nova<C: Compute = Local> {
    vm: NexusVM<MerkleTrie>,
    _compute: PhantomData<C>,
}

impl Prover for Nova<Local> {
    type Memory = MerkleTrie;
    type Params = SeqPP;
    type Proof = IVCProof;
    type Error = ProofError;

    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Nova::<Local> {
            vm: parse_elf::<Self::Memory>(elf_bytes)?,
            _compute: PhantomData,
        })
    }

    fn new_from_file(path: &PathBuf) -> Result<Self, Self::Error> {
        Ok(Nova::<Local> {
            vm: load_elf::<Self::Memory>(path)?,
            _compute: PhantomData,
        })
    }

    fn run<T>(mut self, input: Option<T>) -> Result<(), Self::Error>
    where
        T: Serialize + Sized,
    {
        if let Some(inp) = input {
            self.vm.syscalls.set_input(postcard::to_stdvec(&inp).unwrap().as_slice())
        }

        eval(&mut self.vm, false, false)?;

        // todo: print output? add output tape?

        Ok(())
    }

    fn prove<T>(mut self, pp: &Self::Params, input: Option<T>) -> Result<Self::Proof, Self::Error>
    where
        T: Serialize + Sized,
    {
        if let Some(inp) = input {
            self.vm.syscalls.set_input(postcard::to_stdvec(&inp).unwrap().as_slice())
        }

        let tr = trace(&mut self.vm, K, false)?;
        let pr = prove_seq(pp, tr)?;

        // todo: print output? add output tape?

        Ok(pr)
    }
}

impl Parameterized for SeqPP {
    type Error = ProofError;

    fn generate() -> Result<Self, Self::Error> {
        gen_vm_pp(K, &())
    }

    fn load(path: &PathBuf) -> Result<Self, Self::Error> {
        load_pp(path.to_str().unwrap())
    }

    fn save(pp: &Self, path: &PathBuf) -> Result<(), Self::Error> {
        save_pp(pp, path.to_str().unwrap())
    }
}

impl Verifiable for IVCProof {
    type Params = SeqPP;
    type Error = ProofError;

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error> {
        return Ok(self.verify(pp, self.step_num() as _)?);
    }
}
