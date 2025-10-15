//! Pallas PCS helpers for Vesta-field Halo2 circuits.
//! Orientation: circuit field = Vesta (Fq), commitment group = Pallas G1.
//! This module provides host-side generator derivation and in-circuit
//! scalar-field utilities needed by the polynomial publisher circuit.

use ff::{Field, FromUniformBytes};
use halo2_gadgets::poseidon::primitives::{self as poseidon_primitives, ConstantLength, P128Pow5T3};
use pasta_curves::{
    pallas::{Affine as PallasAffine, Scalar as PallasScalar},
    Fq as Fr, // Circuit scalar field (Vesta field)
};
use pasta_curves::group::{prime::PrimeCurveAffine, Curve};

/// Domain tags (v1)
pub mod domains {
    /// FS challenge domain for publisher
    pub const TAG_FS_PUBLISHER: u64 = 0x50554246; // 'PUBF'
    /// FS binding tag for coeff-commit digest included into r
    pub const TAG_FS_COEF: u64 = 0x46534346; // 'FSCF'
    /// Accumulator hash domain H_A(A_i, P_i)
    pub const TAG_ACC_A: u64 = 0x41434341; // 'ACCA'
    /// Wallet accumulator hash domain H_S(S_i, P_i')
    pub const TAG_ACC_S: u64 = 0x41434353; // 'ACCS'
    /// Aggregator binding domain for next state
    pub const TAG_ACC_AGG: u64 = 0x41474741; // 'AGGA'
    /// P_i' derivation domain (simulate P_i - [alpha]G0)
    pub const TAG_PI_PRIME: u64 = 0x50495052; // 'PIPR'
    /// Coefficient commitment domain tag
    pub const TAG_COEF_COMMIT: u64 = 0x434F4546; // 'COEF'
    /// Unified block gram hash tag
    pub const TAG_UGRAM: u64 = 0x4752414D; // 'GRAM'
    /// Unified block fold/update tag
    pub const TAG_UFOLD: u64 = 0x46554C44; // 'FULD'
}

/// Deterministically derive a vector of Pallas generators G_k using BLAKE3-to-scalar
/// and multiplying the canonical Pallas generator.
pub fn derive_pedersen_generators(count: usize, domain_sep: &[u8]) -> Vec<PallasAffine> {
    use blake3::Hasher;
    let base = <PallasAffine as PrimeCurveAffine>::generator().to_curve();
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        let mut h = Hasher::new();
        h.update(b"tachyon-mini:pcs:gens:v1");
        h.update(domain_sep);
        h.update(&(idx as u64).to_le_bytes());
        let digest = h.finalize();
        // Map 32 bytes uniformly to a scalar
        let mut wide = [0u8; 64];
        {
            let _xof = Hasher::new_derive_key("tachyon-mini:pcs:wide").finalize_xof();
            // Use the digest as seed material; copy into the first 32 bytes; ignore XOF output.
            wide[..32].copy_from_slice(digest.as_bytes());
        }
        let s = PallasScalar::from_uniform_bytes(&wide);
        let g = (base * s).to_affine();
        out.push(g);
    }
    out
}

/// Evaluate a polynomial given by coefficients c[0..=d] at point r using Horner's rule.
/// Returns p(r) in the circuit field (Vesta Fq).
pub fn horner_eval(coeffs: &[Fr], r: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    for &c in coeffs.iter().rev() {
        acc = acc * r + c;
    }
    acc
}

/// Compute \prod_j (r - a_j) over the circuit field (Vesta Fq).
pub fn product_of_differences(r: Fr, roots: &[Fr]) -> Fr {
    let mut acc = Fr::ONE;
    for &a in roots {
        acc *= r - a;
    }
    acc
}

/// Compute a Fiat–Shamir challenge for the publisher using Poseidon2 t=3, rate=2.
/// r = H(TAG_FS_PUBLISHER, ctx1, ctx2)
pub fn fs_challenge_publisher(ctx1: Fr, ctx2: Fr) -> Fr {
    let tag = Fr::from(domains::TAG_FS_PUBLISHER as u64);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().
        hash([tag, ctx1, ctx2])
}

/// Compute H_A(A_i, P_i) where inputs are encoded as two field elements each (x,y).
/// Callers are responsible for encoding Pallas affine coordinates canonically into Fr.
pub fn hash_accumulator_a(a_x: Fr, a_y: Fr, p_x: Fr, p_y: Fr) -> Fr {
    // Compose with two rounds to respect rate=2
    let tag = Fr::from(domains::TAG_ACC_A as u64);
    let d1 = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag, a_x, a_y]);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([d1, p_x, p_y])
}

/// Compute H_S(S_i, P_i') with the same composition as `hash_accumulator_a`.
pub fn hash_accumulator_s(s_x: Fr, s_y: Fr, p_x: Fr, p_y: Fr) -> Fr {
    let tag = Fr::from(domains::TAG_ACC_S as u64);
    let d1 = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag, s_x, s_y]);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([d1, p_x, p_y])
}

/// Commit a coefficient vector using Poseidon (t=3, rate=2) in two-round chaining.
/// Returns C = H(H(TAG, c0, c1), c2, c3) ...; if fewer than 2 remain pad with zero.
pub fn commit_coeffs_poseidon(coeffs: &[Fr]) -> Fr {
    // Domain tag for coeff commitment
    let tag = Fr::from(domains::TAG_COEF_COMMIT as u64);
    let mut acc = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag, coeffs.get(0).copied().unwrap_or(Fr::ZERO), coeffs.get(1).copied().unwrap_or(Fr::ZERO)]);
    let mut idx = 2;
    while idx < coeffs.len() {
        let a = coeffs[idx];
        let b = coeffs.get(idx + 1).copied().unwrap_or(Fr::ZERO);
        acc = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
            .hash([acc, a, b]);
        idx += 2;
    }
    acc
}

/// Compute aggregator next digest: H(TAG_ACC_AGG, A_i_x, A_i_y) then H(d1, P_i_x, P_i_y) then
/// mix in h_i as a final round: H(out, h_i, 0)
pub fn hash_accumulator_next(a_x: Fr, a_y: Fr, p_x: Fr, p_y: Fr, h_i: Fr) -> Fr {
    let tag = Fr::from(domains::TAG_ACC_AGG as u64);
    let d1 = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([tag, a_x, a_y]);
    let d2 = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([d1, p_x, p_y]);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([d2, h_i, Fr::ZERO])
}

/// Derive P_i' digest from P_i and alpha: H(TAG_PI_PRIME, P_i, alpha)
pub fn hash_pi_prime(p_i: Fr, alpha: Fr) -> Fr {
    let tag = Fr::from(domains::TAG_PI_PRIME as u64);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([tag, p_i, alpha])
}

/// Derive a domain-separated digest from a coefficient commitment to bind into r.
/// d_coeff = H(TAG_FS_COEF, coef_commit, 0)
pub fn fs_digest_of_coeff_commit(coef_commit: Fr) -> Fr {
    let tag = Fr::from(domains::TAG_FS_COEF as u64);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag, coef_commit, Fr::ZERO])
}


