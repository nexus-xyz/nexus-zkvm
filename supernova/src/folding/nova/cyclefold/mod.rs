pub(crate) mod nimfs;
pub(crate) mod secondary;

use crate::r1cs::Error as R1CSError;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    R1CS(R1CSError),
    Synthesis(ark_relations::r1cs::SynthesisError),

    #[cfg(any(test, feature = "spartan"))]
    InvalidPublicInput,
}

impl From<R1CSError> for Error {
    fn from(error: R1CSError) -> Self {
        Self::R1CS(error)
    }
}

impl From<ark_relations::r1cs::SynthesisError> for Error {
    fn from(error: ark_relations::r1cs::SynthesisError) -> Self {
        Self::Synthesis(error)
    }
}
