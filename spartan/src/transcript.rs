use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub trait ProofTranscript<G: CurveGroup> {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]);
  fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField);
  fn append_scalars(&mut self, label: &'static [u8], scalars: &[G::ScalarField]);
  fn append_point(&mut self, label: &'static [u8], point: &G);
  fn append_points(&mut self, label: &'static [u8], points: &[G]);
  fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField;
  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<G::ScalarField>;
}

impl<G: CurveGroup> ProofTranscript<G> for Transcript {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]) {
    self.append_message(b"protocol-name", protocol_name);
  }

  fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField) {
    let mut buf = vec![];
    scalar.serialize_compressed(&mut buf).unwrap();
    self.append_message(label, &buf);
  }

  fn append_scalars(&mut self, label: &'static [u8], scalars: &[G::ScalarField]) {
    self.append_message(label, b"begin_append_vector");
    for item in scalars.iter() {
      <Self as ProofTranscript<G>>::append_scalar(self, label, item);
    }
    self.append_message(label, b"end_append_vector");
  }

  fn append_point(&mut self, label: &'static [u8], point: &G) {
    let mut buf = vec![];
    point.serialize_compressed(&mut buf).unwrap();
    self.append_message(label, &buf);
  }

  fn append_points(&mut self, label: &'static [u8], points: &[G]) {
    self.append_message(label, b"begin_append_vector");
    for item in points.iter() {
      self.append_point(label, item);
    }
    self.append_message(label, b"end_append_vector");
  }

  fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
    let mut buf = [0u8; 64];
    self.challenge_bytes(label, &mut buf);
    G::ScalarField::from_le_bytes_mod_order(&buf)
  }

  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<G::ScalarField> {
    (0..len)
      .map(|_i| <Self as ProofTranscript<G>>::challenge_scalar(self, label))
      .collect::<Vec<G::ScalarField>>()
  }
}

pub trait AppendToTranscript<G: CurveGroup> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript);
}

// // impl<G:CurveGroup> AppendToTranscript<G> for G::ScalarField {
// //   fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
// //     transcript.append_scalar(label, self);
// //   }
// // }

// impl<G:CurveGroup> AppendToTranscript<G> for [G::ScalarField] {
//   fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
//     transcript.append_message(label, b"begin_append_vector");
//     for item in self {
//       transcript.append_scalar(label, item);
//     }
//     transcript.append_message(label, b"end_append_vector");
//   }
// }

// impl<G:CurveGroup> AppendToTranscript<G> for G {
//   fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
//     transcript.append_point(label, self);
//   }
// }
