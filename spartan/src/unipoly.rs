use super::commitments::{Commitments, MultiCommitGens};
use super::transcript::{AppendToTranscript, ProofTranscript};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::*;
use merlin::Transcript;

// ax^2 + bx + c stored as vec![c,b,a]
// ax^3 + bx^2 + cx + d stored as vec![d,c,b,a]
#[derive(Debug)]
pub struct UniPoly<F> {
  coeffs: Vec<F>,
}

// ax^2 + bx + c stored as vec![c,a]
// ax^3 + bx^2 + cx + d stored as vec![d,b,a]
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CompressedUniPoly<F: PrimeField> {
  coeffs_except_linear_term: Vec<F>,
}

impl<F: PrimeField> UniPoly<F> {
  pub fn from_evals(evals: &[F]) -> Self {
    // we only support degree-2 or degree-3 univariate polynomials
    assert!(evals.len() == 3 || evals.len() == 4);
    let coeffs = if evals.len() == 3 {
      // ax^2 + bx + c
      let two_inv = F::from(2u64).inverse().unwrap();

      let c = evals[0];
      let a = two_inv * (evals[2] - evals[1] - evals[1] + c);
      let b = evals[1] - c - a;
      vec![c, b, a]
    } else {
      // ax^3 + bx^2 + cx + d
      let two_inv = F::from(2u64).inverse().unwrap();
      let six_inv = F::from(6u64).inverse().unwrap();

      let d = evals[0];
      let a = six_inv
        * (evals[3] - evals[2] - evals[2] - evals[2] + evals[1] + evals[1] + evals[1] - evals[0]);
      let b = two_inv
        * (evals[0] + evals[0] - evals[1] - evals[1] - evals[1] - evals[1] - evals[1]
          + evals[2]
          + evals[2]
          + evals[2]
          + evals[2]
          - evals[3]);
      let c = evals[1] - d - a - b;
      vec![d, c, b, a]
    };

    UniPoly { coeffs }
  }

  pub fn degree(&self) -> usize {
    self.coeffs.len() - 1
  }

  pub fn as_vec(&self) -> Vec<F> {
    self.coeffs.clone()
  }

  pub fn eval_at_zero(&self) -> F {
    self.coeffs[0]
  }

  pub fn eval_at_one(&self) -> F {
    (0..self.coeffs.len()).map(|i| self.coeffs[i]).sum()
  }

  pub fn evaluate(&self, r: &F) -> F {
    let mut eval = self.coeffs[0];
    let mut power = *r;
    for i in 1..self.coeffs.len() {
      eval += power * self.coeffs[i];
      power *= r;
    }
    eval
  }

  pub fn compress(&self) -> CompressedUniPoly<F> {
    let coeffs_except_linear_term = [&self.coeffs[..1], &self.coeffs[2..]].concat();
    assert_eq!(coeffs_except_linear_term.len() + 1, self.coeffs.len());
    CompressedUniPoly {
      coeffs_except_linear_term,
    }
  }

  pub fn commit<G: CurveGroup<ScalarField = F>>(&self, gens: &MultiCommitGens<G>, blind: &F) -> G {
    Commitments::batch_commit(&self.coeffs, blind, gens)
  }
}

impl<F: PrimeField> CompressedUniPoly<F> {
  // we require eval(0) + eval(1) = hint, so we can solve for the linear term as:
  // linear_term = hint - 2 * constant_term - deg2 term - deg3 term
  pub fn decompress(&self, hint: &F) -> UniPoly<F> {
    let mut linear_term =
      *hint - self.coeffs_except_linear_term[0] - self.coeffs_except_linear_term[0];
    for i in 1..self.coeffs_except_linear_term.len() {
      linear_term -= self.coeffs_except_linear_term[i];
    }

    let mut coeffs = vec![self.coeffs_except_linear_term[0], linear_term];
    coeffs.extend(&self.coeffs_except_linear_term[1..]);
    assert_eq!(self.coeffs_except_linear_term.len() + 1, coeffs.len());
    UniPoly { coeffs }
  }
}

impl<G: CurveGroup> AppendToTranscript<G> for UniPoly<G::ScalarField> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"UniPoly_begin");
    for i in 0..self.coeffs.len() {
      <Transcript as ProofTranscript<G>>::append_scalar(transcript, b"coeff", &self.coeffs[i]);
    }
    transcript.append_message(label, b"UniPoly_end");
  }
}

#[cfg(test)]
mod tests {

  use super::*;
  use ark_bls12_381::Fr;

  #[test]
  fn test_from_evals_quad() {
    test_from_evals_quad_helper::<Fr>()
  }

  fn test_from_evals_quad_helper<F: PrimeField>() {
    // polynomial is 2x^2 + 3x + 1
    let e0 = F::one();
    let e1 = F::from(6u64);
    let e2 = F::from(15u64);
    let evals = vec![e0, e1, e2];
    let poly = UniPoly::from_evals(&evals);

    assert_eq!(poly.eval_at_zero(), e0);
    assert_eq!(poly.eval_at_one(), e1);
    assert_eq!(poly.coeffs.len(), 3);
    assert_eq!(poly.coeffs[0], F::one());
    assert_eq!(poly.coeffs[1], F::from(3u64));
    assert_eq!(poly.coeffs[2], F::from(2u64));

    let hint = e0 + e1;
    let compressed_poly = poly.compress();
    let decompressed_poly = compressed_poly.decompress(&hint);
    for i in 0..decompressed_poly.coeffs.len() {
      assert_eq!(decompressed_poly.coeffs[i], poly.coeffs[i]);
    }

    let e3 = F::from(28u64);
    assert_eq!(poly.evaluate(&F::from(3u64)), e3);
  }

  #[test]
  fn test_from_evals_cubic() {
    test_from_evals_cubic_helper::<Fr>()
  }
  fn test_from_evals_cubic_helper<F: PrimeField>() {
    // polynomial is x^3 + 2x^2 + 3x + 1
    let e0 = F::one();
    let e1 = F::from(7u64);
    let e2 = F::from(23u64);
    let e3 = F::from(55u64);
    let evals = vec![e0, e1, e2, e3];
    let poly = UniPoly::from_evals(&evals);

    assert_eq!(poly.eval_at_zero(), e0);
    assert_eq!(poly.eval_at_one(), e1);
    assert_eq!(poly.coeffs.len(), 4);
    assert_eq!(poly.coeffs[0], F::one());
    assert_eq!(poly.coeffs[1], F::from(3u64));
    assert_eq!(poly.coeffs[2], F::from(2u64));
    assert_eq!(poly.coeffs[3], F::one());

    let hint = e0 + e1;
    let compressed_poly = poly.compress();
    let decompressed_poly = compressed_poly.decompress(&hint);
    for i in 0..decompressed_poly.coeffs.len() {
      assert_eq!(decompressed_poly.coeffs[i], poly.coeffs[i]);
    }

    let e4 = F::from(109u64);
    assert_eq!(poly.evaluate(&F::from(4u64)), e4);
  }
}
