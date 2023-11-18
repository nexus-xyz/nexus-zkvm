use crate::random::RandomTape;
use ark_ec::CurveGroup;
use ark_std::rand::{Error, RngCore};

//#[derive(Clone)]
//pub(crate) struct PolyCommitmentTranscript {
//  pub(crate) transcript: Transcript,
//}

impl<G: CurveGroup> RngCore for RandomTape<G> {
  fn fill_bytes(&mut self, dest: &mut [u8]) {
    self.tape.challenge_bytes(b"fill_bytes", dest);
  }

  fn next_u32(&mut self) -> u32 {
    let mut bytes = [0u8; 4];
    self.fill_bytes(&mut bytes);
    u32::from_le_bytes(bytes)
  }

  fn next_u64(&mut self) -> u64 {
    let mut bytes = [0u8; 8];
    self.fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
  }

  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
    self.tape.challenge_bytes(b"try_fill_bytes", dest);
    Ok(())
  }
}

//impl CryptographicSponge for PolyCommitmentTranscript {
//  type Config = &'static [u8];
//  fn new(params: &Self::Config) -> Self {
//    let mut transcript = Self {
//      transcript: Transcript::new(params),
//    };
//    transcript.transcript.append_message(b"PCS", b"PCS");
//    transcript
//  }
//  fn absorb(&mut self, input: &impl Absorb) {
//    self.transcript.append_message(
//      b"absorb_sponge_bytes",
//      (*input).to_sponge_bytes_as_vec().as_slice(),
//    );
//  }
//
//  fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
//    let mut dest = &mut vec![0; num_bytes][..];
//    self.transcript.challenge_bytes(b"squeeze_bytes", dest);
//    dest.to_vec()
//  }
//
//  fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
//    let mut dest = &mut vec![0; num_bits / 8 + 1][..];
//    self.transcript.challenge_bytes(b"squeeze_bits", dest);
//    let mut res = Vec::new();
//    for i in 0..num_bits {
//      if dest[i / 8] & (1 << (i % 8)) != 0 {
//        res.push(true);
//      } else {
//        res.push(false);
//      }
//    }
//    assert_eq!(res.len(), num_bits);
//    res
//  }
//}
//impl From<Transcript> for PolyCommitmentTranscript {
//  fn from(t: Transcript) -> Self {
//    Self { transcript: t }
//  }
//}
//
