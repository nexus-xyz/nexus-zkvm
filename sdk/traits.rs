trait ExecutionState {}
 
enum Uninitialized {};
impl ExecutionState for Uninitialized {};

enum Initialized {};
impl ExecutionState for Initialized {};

enum Evaluated {};
impl ExecutionState for Executed {};

trait Prover {

}


trait Verifiable {
    type Error;

    fn verify(&self) -> Result<(), Self::Error>;
}

trait
