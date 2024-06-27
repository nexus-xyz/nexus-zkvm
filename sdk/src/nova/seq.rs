use crate::traits::*;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 64;

pub struct Nova {
    vm: NexusVM,
    trace: Option<nexus_core::nvm::memory::MerkleTrie::Proof>,
}

impl<S: ExecutionState, C: Compute> Prover<S, C> for Nova {
    type Memory = nexus_core::nvm::memory::MerkleTrie;
    type Params = nexus_core::prover::nova::SeqPP;
    type Proof = nexus_core::prover::nova::types::IVCProof;
    type Error = nexus_core::prover::nova::ProofError;

    fn gen_pp() -> Result<Self::Params, Self::Error> {
        prover::nova::pp::gen_vm_pp(K, &())
    }

    fn load_pp(path: AsRef<Path>) -> Result<Self::Params, Self::Error> {
        prover::nova::pp::load_pp(path)
    }

    fn save_pp(pp: &Self::Params, path: AsRef<Path>) -> Result<(), Self::Error> {
        prover::nova::pp::save_pp(path)
    }
}

impl<C: Compute> Prover<Uninitialized, C> for Nova {

    fn new(elf_bytes: &[u8]) -> Prover<Initialized, C> {
        Prover<Initialized, C> {
            vm: nexus_core::nvm::interactive::parse_elf::<Self::Memory>(elf_bytes),
            trace: None,
        }
    }

    fn new_from_file(path: AsRef<Path>) -> Prover<Initialized, C> {
        Prover<Initialized, C> {
            vm: nexus_core::nvm::interactive::load_elf::<Self::Memory>(path),
            trace: None,
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
//        &self,
//        input: Option<T>
//    ) -> Result<NovaProof, Self::Error> {
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
    ) -> Prover<Evaluated, C>
    where
        T: Serialize + ?Sized,
    {
        if input.is_some() {
            self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
        }

        Prover<Evaluated, C> {
            trace: nexus_core::nvm::interactive::trace(self.vm, K, false),
            ..self,
        }
    }

    /// Execute and locally prove the program.
    fn prove<T, U>(
        &self,
        pp: &Self::Params,
        input: Option<T>
    ) -> Result<(U, NovaProof), Self::Error> {
        if input.is_some() {
            self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
        }

        self.trace = Some(nexus_core::nvm::interactive::trace(self.vm, K, false));

        let proof = nexus_core::prover::nova::prove_seq(&pp, self.trace.unwrap())?;

        if self.vm.output.is_some() {
            let output = postcard::from_bytes::<U>(output)
        }

        Ok(NovaProof(proof), output)
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
    ) -> Result<NovaProof, Self::Error> {
        let proof = nexus_core::prover::nova::prove_seq(&pp, self.trace.unwrap())?;

        Ok(NovaProof(proof))
    }

}

struct NovaProof(Nova::Proof);

impl Verifiable for NovaProof {
    type = Nova::Error;

    fn verify(&self, pp: &Nova::Params) -> Result<(), Nova::Error> {
        self.0.verify(pp, self.0.step_num() as _)
    }

}
