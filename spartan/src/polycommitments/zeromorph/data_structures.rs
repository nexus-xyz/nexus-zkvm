use crate::polycommitments::PolyCommitmentTrait;
use crate::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_poly_commit::{kzg10::Commitment as KZGCommitment, PCCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, vec::Vec};
use merlin::Transcript;

impl<G: CurveGroup, C: PCCommitment> PolyCommitmentTrait<G> for C
where
  C: PartialEq + Debug + AppendToTranscript<G>,
{
  fn zero(_n: usize) -> Self {
    C::empty()
  }
}

impl<E: Pairing> AppendToTranscript<E::G1> for KZGCommitment<E> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_point(label, &self.0.into_group());
  }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct ZeromorphVC<E>
where
  E: Pairing,
{
  comm: KZGCommitment<E>,
}

impl<E> AppendToTranscript<E::G1> for ZeromorphVC<E>
where
  E: Pairing,
{
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    self.comm.append_to_transcript(label, transcript);
  }
}
