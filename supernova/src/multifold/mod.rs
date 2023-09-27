pub(crate) mod nimfs;
pub(crate) mod secondary;

#[derive(Debug, Copy, Clone)]
pub enum Error {
    R1CS(super::r1cs::Error),
    Synthesis(ark_relations::r1cs::SynthesisError),

    #[cfg(test)]
    InvalidPublicInput,
}
