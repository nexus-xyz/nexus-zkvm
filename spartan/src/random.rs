use std::marker::PhantomData;

use super::transcript::ProofTranscript;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::test_rng;
use merlin::Transcript;

pub struct RandomTape<G> {
  tape: Transcript,
  phantom: PhantomData<G>,
}

impl<G: CurveGroup> RandomTape<G> {
  pub fn new(name: &'static [u8]) -> Self {
    let tape = {
      let mut prng = test_rng();
      let mut tape = Transcript::new(name);
      <Transcript as ProofTranscript<G>>::append_scalar(
        &mut tape,
        b"init_randomness",
        &G::ScalarField::rand(&mut prng),
      );
      tape
    };
    Self {
      tape,
      phantom: PhantomData,
    }
  }

  pub fn random_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
    <Transcript as ProofTranscript<G>>::challenge_scalar(&mut self.tape, label)
  }

  pub fn random_vector(&mut self, label: &'static [u8], len: usize) -> Vec<G::ScalarField> {
    <Transcript as ProofTranscript<G>>::challenge_vector(&mut self.tape, label, len)
  }
}
