use crate::traits::*;

use serde::{Deserialize, Serialize};
use std::path::Path;

use nexus_core::nvm::NexusVM;
use nexus_core::nvm::interactive::{load_elf, parse_elf, trace};
use nexus_core::nvm::memory::MerkleTrie;
use nexus_core::prover::nova::types::{SeqPP, IVCProof};
use nexus_core::prover::nova::error::ProofError;
use nexus_core::prover::nova::pp::{gen_vm_pp, load_pp, save_pp};
use nexus_core::prover::nova::prove_seq;

use std::marker::PhantomData;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 64;

struct Uninitialized {}
impl ExecutionState for Uninitialized {};

struct Initialized {
    vm: NexusVM<MerkleTrie>,
}
impl ExecutionState for Initialized {};

struct Traced {
    vm: NexusVM<MerkleTrie>,
    trace: <MerkleTrie as nexus_core::nvm::memory::Memory>::Proof,
}
impl ExecutionState for Traced {};

pub struct Nova<S: ExecutionState = Uninitialized, C: Compute = Local> {
    state: S,
    compute: C,
}

impl<S: ExecutionState, C: Compute> Prover<S, C> for Nova {
    type Memory = MerkleTrie;
    type Params = SeqPP;
    type Proof = IVCProof;
    type Error = ProofError;
}

impl<C: Compute> Prover<Uninitialized, C> for Nova {

    fn new(elf_bytes: &[u8]) -> Self {
        Nova::<Initialized, C> {
            state: Initialized {
                vm: parse_elf::<Self::Memory>(elf_bytes),
            },
            compute: C {},
         }
    }

    fn new_from_file(path: AsRef<Path>) -> Self {
        Nova::<Initialized, C> {
            state: Initialized {
                vm: load_elf::<Self::Memory>(path),
            },
            compute: C {},
        }
    }

}

//impl<C: Compute> Prover<Initialized, C> for Nova {
//
//    todo: add output tape
//    /// Execute the program and return the output.
//    ///
//    /// Allows for checking termination and the output of a program execution before committing to proving.
//    /// However, it requires re-executing the program in order to prove it.
//    fn run<T, U>(
//        &self,
//       input: Option<T>
//    ) -> Result<U, Self::Error>
//    where
//       T: Serialize + ?Sized,
//       U: Deserialize
//    {
//        if input.is_some() {
//            self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
//        }
//
//        nexus_core::nvm::interactive::eval(self.vm, false)?;
//
//        if self.vm.output.is_some() {
//            return Ok(postcard::from_bytes::<U>(output))
//        }
//    }
//
// }
//
//impl Prover<Initialized, Cloud> for Nova {
//
//    todo: finish outsourced proving interfaces
//    /// Remotely prove the program.
//    async fn prove<T, U>(
//        self,
//        input: Option<T>
//    ) -> Result<Self::Proof, Self::Error> {
//       // do something like what is contained in network/rpc/server/bin/client.rs ...
//    }
//
//}

impl Prover<Initialized, Local> for Nova {

    /// Execute the program and generate a trace of the program execution for proving.
    ///
    /// Allows for checking termination and the output ([`Nova::output`]) of a program execution before committing to proving,
    /// and without needing to re-execute the program in order to prove. However, it is slower than [`Nova::run`].
    fn trace<T>(
        self,
        input: Option<T>
    ) -> Self
    where
        T: Serialize + ?Sized,
    {
        if input.is_some() {
            self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
        }

        Nova::<Traced, Local> {
            trace: trace(self.vm, K, false),
            ..self
        }
    }

    /// Execute and locally prove the program.
    fn prove<'a, T, U>(
        self,
        pp: &Self::Params,
        input: Option<T>
    ) -> Result<(U, Self::Proof), Self::Error>
    where
        T: Serialize + ?Sized,
        U: Deserialize<'a>,
    {
        if input.is_some() {
            self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
        }

        self.trace = Some(trace(self.vm, K, false));

        let proof = prove_seq(&pp, self.trace.unwrap())?;

        // todo: add output tape
        // if self.vm.output.is_some() {
        //     let output = postcard::from_bytes::<U>(output)
        // }
        let output = U::default();

        Ok(Self::Proof(proof), output)
    }
}

impl Prover<Traced, Local> for Nova {

    // todo: add output tape
    //
    // fn output<U>(
    //     &self,
    // ) -> Result<U, Self::Error>
    // where
    //     U: Deserialize
    // {
    //     postcard::from_bytes::<U>(output).map_err(Self::Error::from)
    // }

    /// Locally prove the program.
    fn prove(
        self,
        pp: &Self::Params
    ) -> Result<Self::Proof, Self::Error> {
        let proof = prove_seq(&pp, self.trace.unwrap())?;

        Ok(Self::Proof(proof))
    }

}

impl Verifiable for IVCProof {
    type Params = SeqPP;
    type Error = ProofError;

    fn gen_pp() -> Result<Self::Params, Self::Error> {
        gen_vm_pp(K, &())
    }

    fn load_pp(path: AsRef<Path>) -> Result<Self::Params, Self::Error> {
        load_pp(path)
    }

    fn save_pp(pp: &Self::Params, path: AsRef<Path>) -> Result<(), Self::Error> {
        save_pp(path)
    }

    fn verify(&self, pp: &Self::Params) -> Result<(), Self::Error> {
        return self.verify(pp, self.num_steps() as _);
    }
}
