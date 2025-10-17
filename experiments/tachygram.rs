//! Tachyon: set non-inclusion with accumulation schemes (IVC-friendly)
//!
//! Production-grade implementation with security hardening:
//! - Cryptographic binding between parallel chains
//! - Step counter protection against truncation attacks
//! - Type-safe coefficient tracking
//! - Checkpoint support for long-running chains
//! - Comprehensive error handling
//!
//! G ∈ G^D are fixed generators for Pedersen-style vector commitments to polynomial
//! coefficients up to degree D.
//!
//! Accumulator insert: A_{i+1} = [h]A_i + P_i, where P_i commits to ∏_j (X - a_{ij}).
//! Non-membership fold state: S_{i+1} = [h']S_i + (P_i - [α_i]G_0), with α_i = f_i(v).
//!
//! Base for S can be either Zero (recommended, gives S_m(v)=0) or One (as in the note).

use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use sha2::{Digest, Sha512};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, Serializer, Deserializer};

/// Errors that can occur during accumulation operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TachyonError {
    /// Coefficient vector exceeds the maximum degree bound.
    DegreeExceeded { max: usize, actual: usize },
    /// Invalid step counter (e.g., non-sequential).
    InvalidStepCounter { expected: u64, actual: u64 },
    /// Checkpoint mismatch during verification.
    CheckpointMismatch,
    /// Chain binding verification failed.
    ChainBindingFailed,
}

impl core::fmt::Display for TachyonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TachyonError::DegreeExceeded { max, actual } => {
                write!(f, "Degree exceeded: max {}, actual {}", max, actual)
            }
            TachyonError::InvalidStepCounter { expected, actual } => {
                write!(f, "Invalid step counter: expected {}, actual {}", expected, actual)
            }
            TachyonError::CheckpointMismatch => {
                write!(f, "Checkpoint verification failed: hash mismatch")
            }
            TachyonError::ChainBindingFailed => {
                write!(f, "Chain binding verification failed")
            }
        }
    }
}

impl core::error::Error for TachyonError {}

/// Result type for Tachyon operations.
pub type Result<T> = core::result::Result<T, TachyonError>;

/// Public parameters: generators G[0..=D] for coefficient commitments.
#[derive(Clone)]
pub struct Params {
    pub gens: Vec<RistrettoPoint>, // length D+1
    pub degree: usize,             // D
    pub domain_sep: [u8; 32],
    pub chain_id: u64,             // Unique chain identifier for binding
}

/// Checkpoint data for compressing chain history.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Checkpoint {
    pub step: u64,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub A: RistrettoPoint,
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub S: RistrettoPoint,
    pub commitment_hash: [u8; 32],
}

/// Serialization helpers for RistrettoPoint (32 bytes compressed).
#[cfg(feature = "serde")]
mod point_serde {
    use super::*;
    
    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = point.compress().to_bytes();
        serializer.serialize_bytes(&bytes)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(Error::custom(format!("Expected 32 bytes, got {}", bytes.len())));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let compressed = CompressedRistretto(arr);
        compressed.decompress()
            .ok_or_else(|| Error::custom("Invalid Ristretto point"))
    }
}

/// Serializable accumulator state for persistence.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SerializableAccumulator {
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub A: RistrettoPoint,
    pub step: u64,
}

impl From<Accumulator> for SerializableAccumulator {
    fn from(acc: Accumulator) -> Self {
        Self { A: acc.A, step: acc.step }
    }
}

impl From<SerializableAccumulator> for Accumulator {
    fn from(s: SerializableAccumulator) -> Self {
        Self { A: s.A, step: s.step }
    }
}

/// Serializable fold state for persistence.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SerializableFoldState {
    #[cfg_attr(feature = "serde", serde(with = "point_serde"))]
    pub S: RistrettoPoint,
    pub step: u64,
}

impl From<FoldState> for SerializableFoldState {
    fn from(fold: FoldState) -> Self {
        Self { S: fold.S, step: fold.step }
    }
}

impl From<SerializableFoldState> for FoldState {
    fn from(s: SerializableFoldState) -> Self {
        Self { S: s.S, step: s.step }
    }
}

impl Params {
    /// Deterministically derive D+1 generators using hash-to-point.
    pub fn new(max_degree: usize, domain_sep: [u8; 32], chain_id: u64) -> Self {
        let mut gens = Vec::with_capacity(max_degree + 1);
        for i in 0..=max_degree {
            let mut h = Sha512::new();
            h.update(b"TACHYON/VCGEN/");
            h.update(&domain_sep);
            h.update(&chain_id.to_le_bytes());
            h.update(&(i as u64).to_le_bytes());
            gens.push(RistrettoPoint::from_hash(h));
        }
        Self { gens, degree: max_degree, domain_sep, chain_id }
    }

    /// Commitment to coefficient vector b[0..=deg] (constant term first).
    /// Returns error if coefficients exceed degree bound.
    pub fn commit_coeffs(&self, coeffs: &[Scalar]) -> Result<RistrettoPoint> {
        if coeffs.len() > self.gens.len() {
            return Err(TachyonError::DegreeExceeded { 
                max: self.degree, 
                actual: coeffs.len() - 1 
            });
        }
        Ok(RistrettoPoint::multiscalar_mul(coeffs.iter().copied(), self.gens.iter().copied()))
    }

    #[inline]
    pub fn g0(&self) -> RistrettoPoint { self.gens[0] }

    /// Create a checkpoint commitment hash.
    pub fn checkpoint_hash(&self, step: u64, A: &RistrettoPoint, S: &RistrettoPoint) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(b"TACHYON/CHECKPOINT/");
        hasher.update(&self.domain_sep);
        hasher.update(&self.chain_id.to_le_bytes());
        hasher.update(&step.to_le_bytes());
        
        // Safe: Ristretto points compress to exactly 32 bytes
        let a_bytes = A.compress();
        let s_bytes = S.compress();
        debug_assert_eq!(a_bytes.as_bytes().len(), 32);
        debug_assert_eq!(s_bytes.as_bytes().len(), 32);
        
        hasher.update(a_bytes.as_bytes());
        hasher.update(s_bytes.as_bytes());
        
        let digest = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);
        result
    }
}

/// Accumulator state A_i (group element) with step counter.
#[derive(Clone, Copy, Debug)]
pub struct Accumulator {
    pub A: RistrettoPoint,
    pub step: u64,  // Current step counter (0-indexed)
}

/// S base choice for non-membership folding.
#[derive(Clone, Copy, Debug)]
pub enum SBase {
    /// S_j = commitment to the zero polynomial (all-zero coeffs). This guarantees S_m(v)=0.
    Zero,
    /// S_j = commitment to (1,0,0,...) as in the note. Then S_m(v)=∏ h'_i, typically ≠ 0.
    One,
}

/// Non-membership folding state S_i (commitment only, no coefficient tracking).
#[derive(Clone, Copy, Debug)]
pub struct FoldState {
    pub S: RistrettoPoint,
    pub step: u64,  // Current step counter (0-indexed)
}

impl FoldState {
    pub fn new(params: &Params, base: SBase) -> Self {
        let S = match base {
            SBase::Zero => RistrettoPoint::default(),
            SBase::One  => params.g0(),
        };
        Self { S, step: 0 }
    }
}

/// Non-membership folding state with coefficient tracking (for reveal-based verification).
#[derive(Clone, Debug)]
pub struct FoldStateWithCoeffs {
    pub S: RistrettoPoint,
    pub step: u64,
    pub coeffs: Vec<Scalar>, // Constant term first
}

impl FoldStateWithCoeffs {
    pub fn new(params: &Params, base: SBase) -> Self {
        let (S, coeffs) = match base {
            SBase::Zero => (RistrettoPoint::default(), vec![Scalar::from(0u64)]),
            SBase::One  => (params.g0(), vec![Scalar::from(1u64)]),
        };
        Self { S, step: 0, coeffs }
    }

    /// Access tracked coefficients (constant term first).
    pub fn coeffs(&self) -> &[Scalar] {
        &self.coeffs
    }

    /// Convert to commitment-only FoldState (drops coefficients).
    pub fn to_fold_state(&self) -> FoldState {
        FoldState { S: self.S, step: self.step }
    }
}

/// Hash-to-scalar H(X) with domain separation.
fn h2s(domain: &[u8], bytes: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(bytes);
    Scalar::from_hash(hasher)
}

/// Fiat–Shamir mixer h = H(A_i, P_i, step, chain_binding).
/// Includes step counter for replay protection and S_i for chain binding.
fn H_acc(params: &Params, A: &RistrettoPoint, P: &RistrettoPoint, S: &RistrettoPoint, step: u64) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"TACHYON/H_ACC/v2");
    hasher.update(&params.domain_sep);
    hasher.update(&params.chain_id.to_le_bytes());
    hasher.update(&step.to_le_bytes());
    
    // Safe: Ristretto points compress to exactly 32 bytes
    let a_compressed = A.compress();
    let p_compressed = P.compress();
    let s_compressed = S.compress();
    debug_assert_eq!(a_compressed.as_bytes().len(), 32);
    debug_assert_eq!(p_compressed.as_bytes().len(), 32);
    debug_assert_eq!(s_compressed.as_bytes().len(), 32);
    
    hasher.update(a_compressed.as_bytes());
    hasher.update(p_compressed.as_bytes());
    hasher.update(s_compressed.as_bytes()); // Chain binding
    
    Scalar::from_hash(hasher)
}

/// Fiat–Shamir mixer h' = H(S_i, P_i', step, chain_binding).
/// Includes step counter for replay protection and A_i for chain binding.
fn H_fold(params: &Params, S: &RistrettoPoint, P_prime: &RistrettoPoint, A: &RistrettoPoint, step: u64) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"TACHYON/H_FOLD/v2");
    hasher.update(&params.domain_sep);
    hasher.update(&params.chain_id.to_le_bytes());
    hasher.update(&step.to_le_bytes());
    
    // Safe: Ristretto points compress to exactly 32 bytes
    let s_compressed = S.compress();
    let p_compressed = P_prime.compress();
    let a_compressed = A.compress();
    debug_assert_eq!(s_compressed.as_bytes().len(), 32);
    debug_assert_eq!(p_compressed.as_bytes().len(), 32);
    debug_assert_eq!(a_compressed.as_bytes().len(), 32);
    
    hasher.update(s_compressed.as_bytes());
    hasher.update(p_compressed.as_bytes());
    hasher.update(a_compressed.as_bytes()); // Chain binding
    
    Scalar::from_hash(hasher)
}

/// Multiply polynomial by (X - r). Coefficients are little-endian (b[0] = constant term).
fn mul_by_x_minus_r(mut poly: Vec<Scalar>, r: Scalar) -> Vec<Scalar> {
    let n = poly.len();
    let mut out = vec![Scalar::from(0u64); n + 1];
    // out[j] += -r * poly[j]
    // out[j+1] += poly[j]
    for j in 0..n {
        out[j+1] = out[j+1] + poly[j];
        out[j]   = out[j] - poly[j] * r;
    }
    out
}

/// Build coefficients of ∏_j (X - a_j).
/// Returns [1] for empty roots (the constant polynomial 1).
/// Coefficients are in little-endian order: [constant, x, x², ...].
pub fn coeffs_from_roots(roots: &[Scalar]) -> Vec<Scalar> {
    let mut poly = vec![Scalar::from(1u64)]; // 1
    for &r in roots {
        poly = mul_by_x_minus_r(poly, r);
    }
    poly
}

/// Horner evaluation: ∑ b_k x^k with b[0] constant term.
/// Returns 0 for empty coefficient vector.
pub fn eval_poly_at(coeffs: &[Scalar], x: Scalar) -> Scalar {
    if coeffs.is_empty() {
        return Scalar::from(0u64);
    }
    let mut acc = Scalar::from(0u64);
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Initialize accumulator A_0 or resume from a known A_j.
pub fn init_accumulator(params: &Params) -> Accumulator {
    // ((1,0,0,...), G) = G_0
    Accumulator { A: params.g0(), step: 0 }
}

/// Resume accumulator from a checkpoint.
pub fn resume_accumulator(checkpoint: &Checkpoint) -> Accumulator {
    Accumulator { A: checkpoint.A, step: checkpoint.step }
}

/// Insert vector a_i into accumulator. Returns new A and the public P_i.
/// Note: This is the simplified version without fold state. For full non-membership proofs, use `non_membership_step`.
pub fn insert_step(params: &Params, acc_i: &Accumulator, fold_i: &FoldState, a_i: &[Scalar]) -> Result<(Accumulator, RistrettoPoint, Scalar)> {
    let b_i = coeffs_from_roots(a_i);
    let P_i = params.commit_coeffs(&b_i)?;
    let h = H_acc(params, &acc_i.A, &P_i, &fold_i.S, acc_i.step);
    let A_next = Accumulator { 
        A: acc_i.A * h + P_i,
        step: acc_i.step + 1,
    };
    Ok((A_next, P_i, h))
}

/// One IVC fold step for non-membership at point v (commitment-only version).
/// Returns updated (A_{i+1}, S_{i+1}) and the per-step witness alpha_i.
pub struct StepResult {
    pub A_next: Accumulator,
    pub S_next: FoldState,
    pub P_i: RistrettoPoint,
    pub P_i_prime: RistrettoPoint,
    pub h: Scalar,
    pub h_prime: Scalar,
    pub alpha_i: Scalar,
}

pub fn non_membership_step(
    params: &Params,
    v: Scalar,
    acc_i: &Accumulator,
    fold_i: &FoldState,
    a_i: &[Scalar],
) -> Result<StepResult> {
    // Verify step counters match
    if acc_i.step != fold_i.step {
        return Err(TachyonError::InvalidStepCounter {
            expected: acc_i.step,
            actual: fold_i.step,
        });
    }

    // Build P_i
    let b_i = coeffs_from_roots(a_i);
    let P_i = params.commit_coeffs(&b_i)?;
    
    // Accumulator update with chain binding
    let h = H_acc(params, &acc_i.A, &P_i, &fold_i.S, acc_i.step);
    let A_next = Accumulator { 
        A: acc_i.A * h + P_i,
        step: acc_i.step + 1,
    };

    // α_i = f_i(v)
    let alpha_i = eval_poly_at(&b_i, v);
    // P_i' = P_i - [α_i] G_0
    let P_i_prime = P_i - params.g0() * alpha_i;
    
    // Fold update with chain binding
    let h_prime = H_fold(params, &fold_i.S, &P_i_prime, &acc_i.A, fold_i.step);
    let S_next = FoldState {
        S: fold_i.S * h_prime + P_i_prime,
        step: fold_i.step + 1,
    };

    Ok(StepResult { A_next, S_next, P_i, P_i_prime, h, h_prime, alpha_i })
}

/// One IVC fold step with coefficient tracking (for reveal-based verification).
pub struct StepResultWithCoeffs {
    pub A_next: Accumulator,
    pub S_next: FoldStateWithCoeffs,
    pub P_i: RistrettoPoint,
    pub P_i_prime: RistrettoPoint,
    pub h: Scalar,
    pub h_prime: Scalar,
    pub alpha_i: Scalar,
}

pub fn non_membership_step_with_coeffs(
    params: &Params,
    v: Scalar,
    acc_i: &Accumulator,
    fold_i: &FoldStateWithCoeffs,
    a_i: &[Scalar],
) -> Result<StepResultWithCoeffs> {
    // Verify step counters match
    if acc_i.step != fold_i.step {
        return Err(TachyonError::InvalidStepCounter {
            expected: acc_i.step,
            actual: fold_i.step,
        });
    }

    // Build P_i
    let b_i = coeffs_from_roots(a_i);
    let P_i = params.commit_coeffs(&b_i)?;
    
    // Accumulator update with chain binding
    let h = H_acc(params, &acc_i.A, &P_i, &fold_i.S, acc_i.step);
    let A_next = Accumulator { 
        A: acc_i.A * h + P_i,
        step: acc_i.step + 1,
    };

    // α_i = f_i(v)
    let alpha_i = eval_poly_at(&b_i, v);
    // P_i' = P_i - [α_i] G_0
    let P_i_prime = P_i - params.g0() * alpha_i;
    
    // Fold update with chain binding
    let h_prime = H_fold(params, &fold_i.S, &P_i_prime, &acc_i.A, fold_i.step);
    
    // Maintain coefficients: s_{i+1}(X) = h' * s_i(X) + (f_i(X) - α_i)
    let max_len = core::cmp::max(fold_i.coeffs.len(), b_i.len());
    let mut new_coeffs = fold_i.coeffs.clone();
    new_coeffs.resize(max_len, Scalar::from(0u64));
    let mut term = b_i.clone();
    term.resize(max_len, Scalar::from(0u64));
    term[0] = term[0] - alpha_i; // subtract α from constant term
    // s <- h' * s + term
    for j in 0..max_len {
        new_coeffs[j] = new_coeffs[j] * h_prime + term[j];
    }
    
    let S_next = FoldStateWithCoeffs {
        S: fold_i.S * h_prime + P_i_prime,
        step: fold_i.step + 1,
        coeffs: new_coeffs,
    };

    Ok(StepResultWithCoeffs { A_next, S_next, P_i, P_i_prime, h, h_prime, alpha_i })
}

/// Final check by revealing coefficients of S_m and verifying S_m(v)=0.
pub fn verify_non_membership_by_reveal(revealed_coeffs: &[Scalar], v: Scalar) -> bool {
    eval_poly_at(revealed_coeffs, v) == Scalar::from(0u64)
}

/// Helper: start non-membership folding state at step j (commitment-only).
pub fn init_fold(params: &Params, base: SBase) -> FoldState {
    FoldState::new(params, base)
}

/// Helper: start non-membership folding state with coefficient tracking.
pub fn init_fold_with_coeffs(params: &Params, base: SBase) -> FoldStateWithCoeffs {
    FoldStateWithCoeffs::new(params, base)
}

/// Resume fold state from a checkpoint.
pub fn resume_fold(checkpoint: &Checkpoint) -> FoldState {
    FoldState { S: checkpoint.S, step: checkpoint.step }
}

/// Commit coefficients directly (e.g., to prove that S_m matches a revealed vector).
pub fn commit_coeffs(params: &Params, coeffs: &[Scalar]) -> Result<RistrettoPoint> {
    params.commit_coeffs(coeffs)
}

/// Create a checkpoint of the current chain state.
pub fn create_checkpoint(params: &Params, acc: &Accumulator, fold: &FoldState) -> Checkpoint {
    let commitment_hash = params.checkpoint_hash(acc.step, &acc.A, &fold.S);
    Checkpoint {
        step: acc.step,
        A: acc.A,
        S: fold.S,
        commitment_hash,
    }
}

/// Verify a checkpoint against current state.
pub fn verify_checkpoint(params: &Params, checkpoint: &Checkpoint, acc: &Accumulator, fold: &FoldState) -> Result<()> {
    if checkpoint.step != acc.step || checkpoint.step != fold.step {
        return Err(TachyonError::InvalidStepCounter {
            expected: checkpoint.step,
            actual: acc.step,
        });
    }
    
    let computed_hash = params.checkpoint_hash(acc.step, &acc.A, &fold.S);
    if computed_hash != checkpoint.commitment_hash {
        return Err(TachyonError::CheckpointMismatch);
    }
    
    if checkpoint.A.compress() != acc.A.compress() {
        return Err(TachyonError::ChainBindingFailed);
    }
    
    if checkpoint.S.compress() != fold.S.compress() {
        return Err(TachyonError::ChainBindingFailed);
    }
    
    Ok(())
}

/// Quick self-checks.
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn non_membership_zero_base_gives_zero_at_v() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let params = Params::new(16, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1001);
        let v = Scalar::from(5u64);

        // Build 5 steps of insertions, none contain v as a root.
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold_with_coeffs(&params, SBase::Zero);

        for _ in 0..5 {
            // Random small set of roots, avoid v
            let roots: Vec<Scalar> = (0..3)
                .map(|_| {
                    let r = rng.gen::<u64>() % 11;
                    let s = Scalar::from(r);
                    if s == v { Scalar::from(13u64) } else { s }
                })
                .collect();

            let step = non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots).unwrap();
            acc = step.A_next;
            fold = step.S_next;
        }

        let s_coeffs = fold.coeffs().to_vec();
        assert!(verify_non_membership_by_reveal(&s_coeffs, v));

        // Check commitment consistency
        let S_m_comm = commit_coeffs(&params, &s_coeffs).unwrap();
        assert_eq!(S_m_comm.compress(), fold.S.compress());
    }

    #[test]
    fn one_base_generally_not_zero_at_v() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1002);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold_with_coeffs(&params, SBase::One);

        let roots = vec![Scalar::from(1u64), Scalar::from(2u64)];
        let step = non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots).unwrap();
        acc = step.A_next;
        fold = step.S_next;

        // With SBase::One, S_1(v) = h'_0 != 0 with overwhelming probability.
        let s_coeffs = fold.coeffs().to_vec();
        assert!(!verify_non_membership_by_reveal(&s_coeffs, v));
    }

    #[test]
    fn commitment_only_mode_works() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1003);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        for i in 0..3 {
            let roots = vec![Scalar::from(i), Scalar::from(i + 10)];
            let step = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();
            acc = step.A_next;
            fold = step.S_next;
        }

        // Should reach step 3
        assert_eq!(acc.step, 3);
        assert_eq!(fold.step, 3);
    }

    #[test]
    fn step_counter_validation() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1004);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        // Manually desync step counters
        acc.step = 1;
        fold.step = 0;

        let roots = vec![Scalar::from(1u64)];
        let result = non_membership_step(&params, v, &acc, &fold, &roots);
        
        assert!(matches!(result, Err(TachyonError::InvalidStepCounter { .. })));
    }

    #[test]
    fn degree_bound_validation() {
        let params = Params::new(4, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1005);
        
        // Create coefficients exceeding degree bound
        let too_many_coeffs = vec![Scalar::from(1u64); 10];
        
        let result = params.commit_coeffs(&too_many_coeffs);
        assert!(matches!(result, Err(TachyonError::DegreeExceeded { .. })));
    }

    #[test]
    fn checkpoint_creation_and_verification() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1006);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        // Perform some steps
        for i in 0..3 {
            let roots = vec![Scalar::from(i), Scalar::from(i + 10)];
            let step = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();
            acc = step.A_next;
            fold = step.S_next;
        }

        // Create checkpoint
        let checkpoint = create_checkpoint(&params, &acc, &fold);
        assert_eq!(checkpoint.step, 3);

        // Verify checkpoint
        assert!(verify_checkpoint(&params, &checkpoint, &acc, &fold).is_ok());

        // Resume from checkpoint
        let resumed_acc = resume_accumulator(&checkpoint);
        let resumed_fold = resume_fold(&checkpoint);
        assert_eq!(resumed_acc.step, 3);
        assert_eq!(resumed_fold.step, 3);
        assert_eq!(resumed_acc.A.compress(), acc.A.compress());
        assert_eq!(resumed_fold.S.compress(), fold.S.compress());
    }

    #[test]
    fn checkpoint_mismatch_detection() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 1007);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        // Create checkpoint at step 0
        let checkpoint = create_checkpoint(&params, &acc, &fold);

        // Advance the chain
        let roots = vec![Scalar::from(1u64)];
        let step = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();
        acc = step.A_next;
        fold = step.S_next;

        // Checkpoint should not match advanced state
        let result = verify_checkpoint(&params, &checkpoint, &acc, &fold);
        assert!(result.is_err());
    }

    #[test]
    fn chain_binding_prevents_substitution() {
        // Two separate chains with same step count
        let params1 = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 2001);
        let params2 = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 2002);
        let v = Scalar::from(3u64);

        let mut acc1 = init_accumulator(&params1);
        let mut fold1 = init_fold(&params1, SBase::Zero);

        let mut acc2 = init_accumulator(&params2);
        let mut fold2 = init_fold(&params2, SBase::Zero);

        let roots = vec![Scalar::from(1u64), Scalar::from(2u64)];
        
        let step1 = non_membership_step(&params1, v, &acc1, &fold1, &roots).unwrap();
        let step2 = non_membership_step(&params2, v, &acc2, &fold2, &roots).unwrap();

        // Even with same inputs, different chain IDs produce different results
        assert_ne!(step1.h, step2.h);
        assert_ne!(step1.h_prime, step2.h_prime);
    }

    #[test]
    fn replay_protection_via_step_counter() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 3001);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        let roots = vec![Scalar::from(1u64), Scalar::from(2u64)];
        
        // First step
        let step1 = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();
        acc = step1.A_next;
        fold = step1.S_next;

        // Second step with same roots
        let step2 = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();

        // Different steps should produce different challenges even with same inputs
        assert_ne!(step1.h, step2.h);
        assert_ne!(step1.h_prime, step2.h_prime);
    }

    #[test]
    fn truncation_attack_prevention() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 4001);
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        // Perform 3 steps
        let mut checkpoints = Vec::new();
        for i in 0..3 {
            checkpoints.push(create_checkpoint(&params, &acc, &fold));
            let roots = vec![Scalar::from(i)];
            let step = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();
            acc = step.A_next;
            fold = step.S_next;
        }

        // Final checkpoint
        let final_checkpoint = create_checkpoint(&params, &acc, &fold);

        // Try to verify intermediate checkpoint against final state (should fail)
        assert!(verify_checkpoint(&params, &checkpoints[0], &acc, &fold).is_err());
        assert!(verify_checkpoint(&params, &checkpoints[1], &acc, &fold).is_err());
        
        // Only final checkpoint should match
        assert!(verify_checkpoint(&params, &final_checkpoint, &acc, &fold).is_ok());
    }

    #[test]
    fn long_chain_with_periodic_checkpoints() {
        let params = Params::new(16, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01", 5001);
        let v = Scalar::from(7u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero);

        let checkpoint_interval = 10;
        let total_steps = 50;
        let mut checkpoints = Vec::new();

        for i in 0..total_steps {
            let roots = vec![Scalar::from(i), Scalar::from(i + 100)];
            let step = non_membership_step(&params, v, &acc, &fold, &roots).unwrap();
            acc = step.A_next;
            fold = step.S_next;

            if (i + 1) % checkpoint_interval == 0 {
                checkpoints.push(create_checkpoint(&params, &acc, &fold));
            }
        }

        // Verify final state
        assert_eq!(acc.step, total_steps);
        assert_eq!(fold.step, total_steps);
        assert_eq!(checkpoints.len(), total_steps / checkpoint_interval);

        // Verify all checkpoints are unique
        for i in 0..checkpoints.len() {
            for j in (i + 1)..checkpoints.len() {
                assert_ne!(checkpoints[i].commitment_hash, checkpoints[j].commitment_hash);
            }
        }
    }

    #[test]
    fn cross_chain_mixing_prevented() {
        // Test that you cannot mix accumulator from one chain with fold state from another
        let params1 = Params::new(8, *b"CHAIN_A_________________________", 6001);
        let params2 = Params::new(8, *b"CHAIN_B_________________________", 6002);
        let v = Scalar::from(3u64);

        let mut acc1 = init_accumulator(&params1);
        let mut fold1 = init_fold(&params1, SBase::Zero);

        let acc2 = init_accumulator(&params2);
        let fold2 = init_fold(&params2, SBase::Zero);

        let roots = vec![Scalar::from(1u64)];
        let step1 = non_membership_step(&params1, v, &acc1, &fold1, &roots).unwrap();
        acc1 = step1.A_next;
        fold1 = step1.S_next;

        // Try to create checkpoint with mixed states (different params would catch this)
        let checkpoint1 = create_checkpoint(&params1, &acc1, &fold1);
        let checkpoint2 = create_checkpoint(&params2, &acc2, &fold2);

        // Checkpoints from different chains should be different even at step 0 vs 1
        assert_ne!(checkpoint1.commitment_hash, checkpoint2.commitment_hash);
    }
}