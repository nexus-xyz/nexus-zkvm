//! This module is an adaptation of code from the bulletproofs crate.
//! See NOTICE.md for more details
#![allow(non_snake_case)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
use super::super::errors::ProofVerifyError;
use super::super::math::Math;
use super::super::transcript::ProofTranscript;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use ark_serialize::*;
use ark_std::One;
use core::iter;
use merlin::Transcript;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BulletReductionProof<G: CurveGroup> {
  L_vec: Vec<G>,
  R_vec: Vec<G>,
}

impl<G: CurveGroup> BulletReductionProof<G> {
  /// Create an inner-product proof.
  ///
  /// The proof is created with respect to the bases \\(G\\).
  ///
  /// The `transcript` is passed in as a parameter so that the
  /// challenges depend on the *entire* transcript (including parent
  /// protocols).
  ///
  /// The lengths of the vectors must all be the same, and must all be
  /// either 0 or a power of 2.
  pub fn prove(
    transcript: &mut Transcript,
    Q: &G,
    G_vec: &[G],
    H: &G,
    a_vec: &[G::ScalarField],
    b_vec: &[G::ScalarField],
    blind: &G::ScalarField,
    blinds_vec: &[(G::ScalarField, G::ScalarField)],
  ) -> (Self, G, G::ScalarField, G::ScalarField, G, G::ScalarField) {
    // Create slices G, H, a, b backed by their respective
    // vectors.  This lets us reslice as we compress the lengths
    // of the vectors in the main loop below.
    let mut G: &mut [G] = &mut G_vec.to_owned()[..];
    let mut a: &mut [G::ScalarField] = &mut a_vec.to_owned()[..];
    let mut b: &mut [G::ScalarField] = &mut b_vec.to_owned()[..];

    // All of the input vectors must have a length that is a power of two.
    let mut n = G.len();
    assert!(n.is_power_of_two());
    let lg_n = n.log_2() as usize;

    // All of the input vectors must have the same length.
    assert_eq!(G.len(), n);
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);
    assert_eq!(blinds_vec.len(), 2 * lg_n);

    let mut L_vec = Vec::with_capacity(lg_n);
    let mut R_vec = Vec::with_capacity(lg_n);
    let mut blinds_iter = blinds_vec.iter();
    let mut blind_fin = *blind;

    while n != 1 {
      n /= 2;
      let (a_L, a_R) = a.split_at_mut(n);
      let (b_L, b_R) = b.split_at_mut(n);
      let (G_L, G_R) = G.split_at_mut(n);

      let c_L = inner_product(a_L, b_R);
      let c_R = inner_product(a_R, b_L);

      let (blind_L, blind_R) = blinds_iter.next().unwrap();

      let scalars = a_L
        .iter()
        .chain(iter::once(&c_L))
        .chain(iter::once(blind_L))
        .copied()
        .collect::<Vec<_>>();

      let bases = G_R
        .iter()
        .chain(iter::once(Q))
        .chain(iter::once(H))
        .copied()
        .collect::<Vec<_>>();

      let bases = G::normalize_batch(bases.as_ref());

      let L = VariableBaseMSM::msm(bases.as_ref(), scalars.as_ref()).unwrap();

      let scalars = a_R
        .iter()
        .chain(iter::once(&c_R))
        .chain(iter::once(blind_R))
        .copied()
        .collect::<Vec<_>>();

      let bases = G_L
        .iter()
        .chain(iter::once(Q))
        .chain(iter::once(H))
        .copied()
        .collect::<Vec<_>>();

      let bases = G::normalize_batch(bases.as_ref());

      let R = VariableBaseMSM::msm(bases.as_ref(), scalars.as_ref()).unwrap();

      <Transcript as ProofTranscript<G>>::append_point(transcript, b"L", &L);
      <Transcript as ProofTranscript<G>>::append_point(transcript, b"R", &R);

      let u = <Transcript as ProofTranscript<G>>::challenge_scalar(transcript, b"u");

      let u_inv = u.inverse().unwrap();

      for i in 0..n {
        a_L[i] = a_L[i] * u + u_inv * a_R[i];
        b_L[i] = b_L[i] * u_inv + u * b_R[i];

        G_L[i] = G_L[i] * u_inv + G_R[i] * u;
      }

      blind_fin = blind_fin + *blind_L * u * u + *blind_R * u_inv * u_inv;

      L_vec.push(L);
      R_vec.push(R);

      a = a_L;
      b = b_L;
      G = G_L;
    }

    let Gamma_hat = G[0] * a[0] + *Q * a[0] * b[0] + *H * blind_fin;

    (
      BulletReductionProof { L_vec, R_vec },
      Gamma_hat,
      a[0],
      b[0],
      G[0],
      blind_fin,
    )
  }

  /// Computes three vectors of verification scalars \\([u\_{i}^{2}]\\), \\([u\_{i}^{-2}]\\) and \\([s\_{i}]\\) for combined multiscalar multiplication
  /// in a parent protocol. See [inner product protocol notes](index.html#verification-equation) for details.
  /// The verifier must provide the input length \\(n\\) explicitly to avoid unbounded allocation within the inner product proof.
  fn verification_scalars(
    &self,
    n: usize,
    transcript: &mut Transcript,
  ) -> Result<
    (
      Vec<G::ScalarField>,
      Vec<G::ScalarField>,
      Vec<G::ScalarField>,
    ),
    ProofVerifyError,
  > {
    let lg_n = self.L_vec.len();
    if lg_n >= 32 {
      // 4 billion multiplications should be enough for anyone
      // and this check prevents overflow in 1<<lg_n below.
      return Err(ProofVerifyError::InternalError);
    }
    if n != (1 << lg_n) {
      return Err(ProofVerifyError::InternalError);
    }

    // 1. Recompute x_k,...,x_1 based on the proof transcript
    let mut challenges = Vec::with_capacity(lg_n);
    for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
      <Transcript as ProofTranscript<G>>::append_point(transcript, b"L", L);
      <Transcript as ProofTranscript<G>>::append_point(transcript, b"R", R);
      challenges.push(<Transcript as ProofTranscript<G>>::challenge_scalar(
        transcript, b"u",
      ));
    }

    // 2. Compute 1/(u_k...u_1) and 1/u_k, ..., 1/u_1
    // let mut challenges_inv = challenges.clone();
    let mut challenges_inv = challenges
      .iter()
      .map(|x| x.inverse().unwrap())
      .collect::<Vec<_>>();
    let mut all_inv = G::ScalarField::one();
    challenges_inv.iter().for_each(|c| all_inv *= *c);

    // 3. Compute u_i^2 and (1/u_i)^2
    for i in 0..lg_n {
      challenges[i] = challenges[i].square();
      challenges_inv[i] = challenges_inv[i].square();
    }
    let challenges_sq = challenges;
    let challenges_inv_sq = challenges_inv;

    // 4. Compute s values inductively.
    let mut s = vec![all_inv];
    for i in 1..n {
      let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
      let k = 1 << lg_i;
      // The challenges are stored in "creation order" as [u_k,...,u_1],
      // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
      let u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
      s.push(s[i - k] * u_lg_i_sq);
    }

    Ok((challenges_sq, challenges_inv_sq, s))
  }

  /// This method is for testing that proof generation work,
  /// but for efficiency the actual protocols would use `verification_scalars`
  /// method to combine inner product verification with other checks
  /// in a single multiscalar multiplication.
  pub fn verify(
    &self,
    n: usize,
    a: &[G::ScalarField],
    transcript: &mut Transcript,
    Gamma: &G,
    G: &[G],
  ) -> Result<(G, G, G::ScalarField), ProofVerifyError> {
    let (u_sq, u_inv_sq, s) = self.verification_scalars(n, transcript)?;

    let group_element = G::normalize_batch(G);

    let G_hat = VariableBaseMSM::msm(group_element.as_ref(), s.as_ref()).unwrap();

    let a_hat = inner_product(a, &s);

    let bases = G::normalize_batch(
      [self.L_vec.as_slice(), self.R_vec.as_slice(), &[*Gamma]]
        .concat()
        .as_ref(),
    );
    let scalars = u_sq
      .into_iter()
      .chain(u_inv_sq.into_iter())
      .chain([G::ScalarField::one()])
      .collect::<Vec<_>>();

    let Gamma_hat = VariableBaseMSM::msm(bases.as_ref(), scalars.as_ref()).unwrap();

    Ok((G_hat, Gamma_hat, a_hat))
  }
}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
  assert!(
    a.len() == b.len(),
    "inner_product(a,b): lengths of vectors do not match"
  );
  let mut out = F::zero();
  for i in 0..a.len() {
    out += a[i] * b[i];
  }
  out
}
