use crate::traits::*;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 64;

trait Prover<S: ExecutionState = Uninitialized, C: Compute = Local> {
    type Memory;
    type Params;
    type Proof;
    type Error;
}

trait Verifiable {
    type Error;

    fn verify(&self) -> Result<(), Self::Error>;
}

struct Nova {
    vm: NexusVM,
    trace: Option<nexus_api::nvm::memory::MerkleTrie::Proof>,
}

impl Prover for Nova {
    type Memory = nexus_api::nvm::memory::MerkleTrie;
    type Params = nexus_api::prover::nova::SeqPP;
    type Proof = nexus_api::prover::nova::types::IVCProof;
    type Error = nexus_api::prover::nova::ProofError;

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
            vm: nexus_api::nvm::interactive::parse_elf::<Self::Memory>(path),
            trace: None,
        }
    }

    fn new_from_file(path: AsRef<Path>) -> Prover<Initialized, C> {
        Prover<Initialized, C> {
            vm: nexus_api::nvm::interactive::parse_elf::<Self::Memory>(path),
            trace: None,
        }
    }

}

// impl<C: Compute> Prover<Initialized, C> for Nova {
//
    // todo: add output tape
    // /// Execute the program and return the output.
    // ///
    // /// Allows for checking termination and the output of a program execution before committing to proving.
    // /// However, it requires re-executing the program in order to prove it.
    // fn run<T, U>(
    //     &self,
    //    input: Option<T>
    // ) -> Result<U, Self::Error>
    // where
    //    T: Serialize + ?Sized,
    //    U: Deserialize
    // {
    //     if input.is_some() {
    //         self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
    //     }
    //
    //     nexus_api::nvm::interactive::eval(self.vm, false)?;
    //
    //     if self.vm.output.is_some() {
    //         return Ok(postcard::from_bytes::<U>(output))
    //     }
    // }
//
// }

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
            trace: nexus_api::nvm::interactive::trace(self.vm, K, false),
            ..self,
        }
    }

    /// Execute and locally prove the program.
    fn prove<T, U>(
        &self,
        input: Option<T>
    ) -> Result<(U, NovaProof), Self::Error> {
        if input.is_some() {
            self.vm.set_input(postcard::to_slice(input.unwrap()).unwrap())
        }

        self.trace = Some(nexus_api::nvm::interactive::trace(self.vm, K, false));

        let proof = nexus_api::prover::nova::prove_seq(&pp, self.trace.unwrap())?;

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
        let proof = nexus_api::prover::nova::prove_seq(&pp, self.trace.unwrap())?;

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
