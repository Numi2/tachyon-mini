//! Tachyon: set non-inclusion with accumulation schemes (IVC-friendly)
//!
//! G ∈ G^D are fixed generators for Pedersen-style vector commitments to polynomial
//! coefficients up to degree D.
//!NumanT
//! Accumulator insert: A_{i+1} = [h]A_i + P_i, where P_i commits to ∏_j (X - a_{ij}).
//! Non-membership fold state: S_{i+1} = [h’]S_i + (P_i - [α_i]G_0), with α_i = f_i(v).
//! Numiiiiii
//! Base for S can be either Zero (recommended, gives S_m(v)=0) or One (as in the note).

use core::ops::{Add, AddAssign, Mul, Sub};
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::MultiscalarMul,
};
use sha2::{Digest, Sha512};

/// Public parameters: generators G[0..=D] for coefficient commitments...
#[derive(Clone)]
pub struct Params {
    pub gens: Vec<RistrettoPoint>, // length D+1
    pub degree: usize,             // D
    pub domain_sep: [u8; 32],
}

impl Params {
    /// Deterministically derive D+1 generators using hash-to-point.
    pub fn new(max_degree: usize, domain_sep: [u8; 32]) -> Self {
        let mut gens = Vec::with_capacity(max_degree + 1);
        for i in 0..=max_degree {
            let mut h = Sha512::new();
            h.update(b"TACHYON/VCGEN/");
            h.update(&domain_sep);
            h.update(&(i as u64).to_le_bytes());
            gens.push(RistrettoPoint::from_hash(h));
        }
        Self { gens, degree: max_degree, domain_sep }
    }

    /// Commitment to coefficient vector b[0..=deg] (constant term first).
    pub fn commit_coeffs(&self, coeffs: &[Scalar]) -> RistrettoPoint {
        assert!(coeffs.len() <= self.gens.len(), "coeffs exceed degree bound");
        RistrettoPoint::multiscalar_mul(coeffs.iter().copied(), self.gens.iter().copied())
    }

    #[inline]
    pub fn g0(&self) -> RistrettoPoint { self.gens[0] }
}

/// Accumulator state A_i (group element).
#[derive(Clone, Copy, Debug)]
pub struct Accumulator {
    pub A: RistrettoPoint,
}

/// S base choice for non-membership folding.
#[derive(Clone, Copy, Debug)]
pub enum SBase {
    /// S_j = commitment to the zero polynomial (all-zero coeffs). This guarantees S_m(v)=0.
    Zero,
    /// S_j = commitment to (1,0,0,...) as in the note. Then S_m(v)=∏ h'_i, typically ≠ 0.
    One,
}

/// Non-membership folding state S_i, optionally tracking coefficients (to allow “reveal”).
#[derive(Clone, Debug)]
pub struct FoldState {
    pub S: RistrettoPoint,
    track_coeffs: bool,
    coeffs: Vec<Scalar>, // if track_coeffs=false this stays empty
}

impl FoldState {
    pub fn new(params: &Params, base: SBase, track_coeffs: bool) -> Self {
        let (S, coeffs) = match base {
            SBase::Zero => (RistrettoPoint::default(), vec![Scalar::from(0u64)]),
            SBase::One  => (params.g0(), vec![Scalar::from(1u64)]),
        };
        Self { S, track_coeffs, coeffs }
    }

    /// Access tracked coefficients (if enabled). Constant term first.
    pub fn coeffs(&self) -> Option<&[Scalar]> {
        if self.track_coeffs { Some(&self.coeffs) } else { None }
    }
}

/// Hash-to-scalar H(X) with domain separation.
fn h2s(domain: &[u8], bytes: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(bytes);
    Scalar::from_hash(hasher)
}

/// Fiat–Shamir mixer h = H(A_i, P_i).
fn H_acc(params: &Params, A: &RistrettoPoint, P: &RistrettoPoint) -> Scalar {
    let mut v = Vec::with_capacity(2 * 32 + params.domain_sep.len());
    v.extend_from_slice(&params.domain_sep);
    v.extend_from_slice(A.compress().as_bytes());
    v.extend_from_slice(P.compress().as_bytes());
    h2s(b"TACHYON/H_ACC", &v)
}

/// Fiat–Shamir mixer h' = H(S_i, P_i').
fn H_fold(params: &Params, S: &RistrettoPoint, P_prime: &RistrettoPoint) -> Scalar {
    let mut v = Vec::with_capacity(2 * 32 + params.domain_sep.len());
    v.extend_from_slice(&params.domain_sep);
    v.extend_from_slice(S.compress().as_bytes());
    v.extend_from_slice(P_prime.compress().as_bytes());
    h2s(b"TACHYON/H_FOLD", &v)
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
pub fn coeffs_from_roots(roots: &[Scalar]) -> Vec<Scalar> {
    let mut poly = vec![Scalar::from(1u64)]; // 1
    for &r in roots {
        poly = mul_by_x_minus_r(poly, r);
    }
    poly
}

/// Horner evaluation: ∑ b_k x^k with b[0] constant term.
pub fn eval_poly_at(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::from(0u64);
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Initialize accumulator A_0 or resume from a known A_j.
pub fn init_accumulator(params: &Params) -> Accumulator {
    // ((1,0,0,...), G) = G_0
    Accumulator { A: params.g0() }
}

/// Insert vector a_i into accumulator. Returns new A and the public P_i.
pub fn insert_step(params: &Params, acc_i: &Accumulator, a_i: &[Scalar]) -> (Accumulator, RistrettoPoint, Scalar) {
    let b_i = coeffs_from_roots(a_i);
    let P_i = params.commit_coeffs(&b_i);
    let h   = H_acc(params, &acc_i.A, &P_i);
    let A_next = Accumulator { A: acc_i.A * h + P_i };
    (A_next, P_i, h)
}

/// One IVC fold step for non-membership at point v.
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
) -> StepResult {
    // Build P_i
    let b_i = coeffs_from_roots(a_i);
    let P_i = params.commit_coeffs(&b_i);
    // Accumulator update
    let h = H_acc(params, &acc_i.A, &P_i);
    let A_next = Accumulator { A: acc_i.A * h + P_i };

    // α_i = f_i(v)
    let alpha_i = eval_poly_at(&b_i, v);
    // P_i' = P_i - [α_i] G_0
    let P_i_prime = P_i - params.g0() * alpha_i;
    // Fold update
    let h_prime = H_fold(params, &fold_i.S, &P_i_prime);
    let mut S_next = FoldState {
        S: fold_i.S * h_prime + P_i_prime,
        track_coeffs: fold_i.track_coeffs,
        coeffs: if fold_i.track_coeffs { fold_i.coeffs.clone() } else { Vec::new() },
    };

    // Maintain coefficients if enabled: s_{i+1}(X) = h' * s_i(X) + (f_i(X) - α_i)
    if S_next.track_coeffs {
        // Resize s and b to same length
        let max_len = core::cmp::max(S_next.coeffs.len(), b_i.len());
        S_next.coeffs.resize(max_len, Scalar::from(0u64));
        let mut term = b_i.clone();
        term.resize(max_len, Scalar::from(0u64));
        term[0] = term[0] - alpha_i; // subtract α from constant term
        // s <- h' * s + term
        for j in 0..max_len {
            S_next.coeffs[j] = S_next.coeffs[j] * h_prime + term[j];
        }
    }

    StepResult { A_next, S_next, P_i, P_i_prime, h, h_prime, alpha_i }
}

/// Final check by revealing coefficients of S_m and verifying S_m(v)=0.
pub fn verify_non_membership_by_reveal(revealed_coeffs: &[Scalar], v: Scalar) -> bool {
    eval_poly_at(revealed_coeffs, v) == Scalar::from(0u64)
}

/// Helper: start non-membership folding state at step j.
pub fn init_fold(params: &Params, base: SBase, track_coeffs: bool) -> FoldState {
    FoldState::new(params, base, track_coeffs)
}

/// Commit coefficients directly (e.g., to prove that S_m matches a revealed vector).
pub fn commit_coeffs(params: &Params, coeffs: &[Scalar]) -> RistrettoPoint {
    params.commit_coeffs(coeffs)
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
        let params = Params::new(16, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01!!");
        let v = Scalar::from(5u64);

        // Build 5 steps of insertions, none contain v as a root.
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::Zero, /*track_coeffs=*/true);

        for _ in 0..5 {
            // Random small set of roots, avoid v
            let roots: Vec<Scalar> = (0..3)
                .map(|_| {
                    let r = rng.gen::<u64>() % 11;
                    let s = Scalar::from(r);
                    if s == v { Scalar::from(13u64) } else { s }
                })
                .collect();

            let step = non_membership_step(&params, v, &acc, &fold, &roots);
            acc = step.A_next;
            fold = step.S_next;
        }

        let s_coeffs = fold.coeffs().unwrap().to_vec();
        assert!(verify_non_membership_by_reveal(&s_coeffs, v));

        // Check commitment consistency
        let S_m_comm = commit_coeffs(&params, &s_coeffs);
        assert_eq!(S_m_comm.compress(), fold.S.compress());
    }

    #[test]
    fn one_base_generally_not_zero_at_v() {
        let params = Params::new(8, *b"TACHYON-ACCUM-RISTRETTO-TEST-V01!!");
        let v = Scalar::from(3u64);
        let mut acc = init_accumulator(&params);
        let mut fold = init_fold(&params, SBase::One, true);

        let roots = vec![Scalar::from(1u64), Scalar::from(2u64)];
        let step = non_membership_step(&params, v, &acc, &fold, &roots);
        acc = step.A_next;
        fold = step.S_next;

        // With SBase::One, S_1(v) = h'_0 != 0 with overwhelming probability.
        let s_coeffs = fold.coeffs().unwrap().to_vec();
        assert!(!verify_non_membership_by_reveal(&s_coeffs, v));
    }
}