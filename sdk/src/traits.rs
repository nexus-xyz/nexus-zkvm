trait ExecutionState {}

enum Uninitialized {}
impl ExecutionState for Uninitialized {}

enum Initialized {}
impl ExecutionState for Initialized {}

enum Traced {}
impl ExecutionState for Traced {}

trait Compute {}

enum Local {}
impl Compute for Local {}

//enum Cloud {}
//impl Cloud for Compute {}

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
