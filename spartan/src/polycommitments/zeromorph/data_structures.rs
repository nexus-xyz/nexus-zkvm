use crate::{
  polycommitments::{PolyCommitmentTrait, SRSTrait},
  transcript::{AppendToTranscript, ProofTranscript},
};
use ark_ec::{
  pairing::Pairing,
  short_weierstrass::{Projective, SWCurveConfig},
  AffineRepr,
};
use ark_poly_commit::{
  kzg10::{Commitment as KZGCommitment, Powers},
  PCCommitment, PCUniversalParams,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  borrow::Cow,
  collections::BTreeMap,
  fmt::Debug,
  ops::{Add, AddAssign, Mul, MulAssign},
  vec::Vec,
};
use derivative::Derivative;
use merlin::Transcript;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZeromorphProof<E>
where
  E: Pairing,
{
  pub proof: KZGCommitment<E>,
  pub quotient_commitments: Vec<KZGCommitment<E>>,
  pub combined_shifted_commitment: KZGCommitment<E>,
}

/// Since we do not support ZK/hiding commitments, we can use a smaller SRS than the KZG implementation.
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
  Clone(bound = ""),
  Debug(bound = ""),
  PartialEq(bound = ""),
  Eq(bound = "")
)]
pub struct ZeromorphSRS<E>
where
  E: Pairing,
{
  /// The maximum number of variables supported by the SRS
  pub max_num_vars: usize,
  /// Group elements of the form { \tau^i g } for i from 0 to N_max
  pub powers_of_tau_g: Vec<E::G1Affine>,
  /// The generator of G2
  pub h: E::G2Affine,
  /// {\tau^(N_max - 2^n + 1) h}_(n=0)^(lg_2(N_max)) times the above generator of G2
  pub shift_powers_of_tau_h: BTreeMap<usize, E::G2Affine>,
}

impl<E: Pairing> SRSTrait for ZeromorphSRS<E> {
  fn max_num_vars(&self) -> usize {
    self.max_num_vars
  }
}

impl<E> PCUniversalParams for ZeromorphSRS<E>
where
  E: Pairing,
{
  /// This is N_max - 1, the maximum degree of univariate polynomials that can be committed to with the
  /// underlying KZG key. It's equal to 2^n where n is the maximum number of variables supported by the SRS.
  fn max_degree(&self) -> usize {
    self.powers_of_tau_g.len() - 1
  }
}

/// The 'ZeromorphCommitterKey' is a truncated version of the SRS containing the G1 elements
/// needed to commit to polynomials and to compute evaluation proofs.
#[derive(Derivative, CanonicalDeserialize, CanonicalSerialize)]
#[derivative(Hash(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct ZeromorphCommitterKey<E>
where
  E: Pairing,
{
  /// Underlying KZG committer key: {\tau^n g}_{n=0}^{2^(num_vars) - 1}
  pub powers_of_tau_g: Vec<E::G1Affine>,
  /// Powers shifted for degree check commitment to be used in evaluation proofs.
  pub shifted_powers_of_tau_g: Vec<E::G1Affine>,
  /// Size of the SRS from which this key was derived
  pub N_max: usize,
  /// Number of variables for which this key was trimmed
  pub num_vars: usize,
}

impl<E: Pairing> ZeromorphCommitterKey<E> {
  /// Gets the number of variables for which this key was initialized
  pub fn supported_num_vars(&self) -> usize {
    self.num_vars
  }
  /// Extracts the vector of powers {\tau^i * g}_{i=0}^{2^{num_vars} - 1}
  pub fn powers(&self) -> Powers<E> {
    Powers {
      powers_of_g: self.powers_of_tau_g.as_slice().into(),
      powers_of_gamma_g: Cow::Borrowed(&[]),
    }
  }
  /// Extracts the vector of shifted powers {\tau^(N_max - 2^num_vars + i) * g}_{i=0}^{2^{num_vars} - 1}
  pub fn shifted_powers(&self) -> Powers<E> {
    Powers {
      powers_of_g: self.shifted_powers_of_tau_g.as_slice().into(),
      powers_of_gamma_g: Cow::Borrowed(&[]),
    }
  }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
  Default(bound = ""),
  Clone(bound = ""),
  Debug(bound = ""),
  PartialEq(bound = ""),
  Eq(bound = "")
)]
pub struct ZeromorphVerifierKey<E>
where
  E: Pairing,
{
  /// The number of variables for which this key was prepared
  pub supported_num_vars: usize,
  /// The generator of G1.
  pub g: E::G1Affine,
  /// The generator of G2.
  pub h: E::G2Affine,
  /// \tau times the above generator of G2.
  pub tau_h: E::G2Affine,
  /// \tau^(N_max - 2^supported_num_vars + 1) times the above generator of G2.
  pub shifted_tau_h: E::G2Affine,
}
#[derive(
  Clone, Copy, Derivative, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Debug,
)]
#[derivative(Default(bound = ""))]
pub struct ZeromorphCommitment<E>
where
  E: Pairing,
{
  pub commitment: KZGCommitment<E>,
}

impl<E, G> From<Projective<G>> for ZeromorphCommitment<E>
where
  G: SWCurveConfig,
  E: Pairing<G1 = Projective<G>>,
{
  fn from(commitment: Projective<G>) -> Self {
    Self {
      commitment: KZGCommitment(commitment.into()),
    }
  }
}

impl<E, G> From<ZeromorphCommitment<E>> for Projective<G>
where
  G: SWCurveConfig,
  E: Pairing<G1 = Projective<G>>,
{
  fn from(commitment: ZeromorphCommitment<E>) -> Self {
    commitment.commitment.0.into()
  }
}

impl<E: Pairing> AppendToTranscript<E::G1> for KZGCommitment<E> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_point(label, &self.0.into_group());
  }
}

impl<E: Pairing> AppendToTranscript<E::G1> for ZeromorphCommitment<E> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    self.commitment.append_to_transcript(label, transcript);
  }
}

impl<E: Pairing> Mul<E::ScalarField> for ZeromorphCommitment<E> {
  type Output = Self;
  fn mul(self, scalar: E::ScalarField) -> Self::Output {
    Self {
      commitment: KZGCommitment((self.commitment.0 * scalar).into()),
    }
  }
}

impl<E: Pairing> MulAssign<E::ScalarField> for ZeromorphCommitment<E> {
  fn mul_assign(&mut self, scalar: E::ScalarField) {
    *self = *self * scalar;
  }
}

impl<E: Pairing> Add<Self> for ZeromorphCommitment<E> {
  type Output = Self;
  fn add(self, other: Self) -> Self::Output {
    Self {
      commitment: KZGCommitment((self.commitment.0 + other.commitment.0).into()),
    }
  }
}

impl<E: Pairing> AddAssign<Self> for ZeromorphCommitment<E> {
  fn add_assign(&mut self, other: Self) {
    *self = *self + other;
  }
}

impl<E: Pairing> From<Vec<E::G1>> for ZeromorphCommitment<E> {
  fn from(C: Vec<E::G1>) -> ZeromorphCommitment<E> {
    assert!(C.len() == 1);
    Self {
      commitment: KZGCommitment(C[0].into()),
    }
  }
}

impl<E: Pairing> From<ZeromorphCommitment<E>> for Vec<E::G1> {
  fn from(c: ZeromorphCommitment<E>) -> Vec<E::G1> {
    vec![c.commitment.0.into()]
  }
}

impl<E: Pairing> PolyCommitmentTrait<E::G1> for ZeromorphCommitment<E> {
  fn zero(_n: usize) -> Self {
    Self {
      commitment: KZGCommitment::empty(),
    }
  }

  fn into_single(self) -> E::G1 {
    self.commitment.0.into()
  }
}
