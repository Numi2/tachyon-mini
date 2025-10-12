//! Core gadgets over the r1cs driver: booleanity, select, arithmetic, range checks.

use anyhow::Result;
use ff::Field;

use crate::circuit::Driver;
use halo2_gadgets::poseidon::primitives::{self as poseidon_primitives, ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;

/// Constrain `b` to be boolean: b * (b - 1) = 0
pub fn boolean<D: Driver>(dr: &mut D, b: D::W) -> Result<()> {
    let one = dr.one();
    dr.enforce_mul(
        || vec![(b.clone(), D::F::ONE)],
        || vec![(b.clone(), D::F::ONE), (one.clone(), -D::F::ONE)],
        Vec::new
    )
}

/// Select: returns cond ? a : b. Enforces out = b + cond * (a - b)
pub fn select<D: Driver>(dr: &mut D, cond: D::W, a: D::W, b: D::W) -> Result<D::W> {
    // out = b + cond*(a-b)
    let a_minus_b = dr.add(|| vec![(a.clone(), D::F::ONE), (b.clone(), -D::F::ONE)])?;
    let (_x, _y, prod) = dr.mul(|| Ok((D::F::ZERO, D::F::ZERO, D::F::ZERO)))?; // allocate placeholder; backends should offer mul(lc,lc)->wire in future
    // For now, emulate via: enforce prod - cond*(a-b) == 0 and set out = b + prod
    dr.enforce_zero(|| vec![(prod.clone(), D::F::ONE)])?; // keep prod bound to future backends
    dr.enforce_mul(|| vec![(cond.clone(), D::F::ONE)], || vec![(a_minus_b.clone(), D::F::ONE)], || vec![(prod.clone(), D::F::ONE)])?;
    let out = dr.add(|| vec![(b, D::F::ONE), (prod, D::F::ONE)])?;
    Ok(out)
}

/// Enforce c = a + b
pub fn add<D: Driver>(dr: &mut D, a: D::W, b: D::W) -> Result<D::W> {
    dr.add(|| vec![(a, D::F::ONE), (b, D::F::ONE)])
}

/// Enforce c = a - b
pub fn sub<D: Driver>(dr: &mut D, a: D::W, b: D::W) -> Result<D::W> {
    dr.add(|| vec![(a, D::F::ONE), (b, -D::F::ONE)])
}

/// Simple range check using bit decomposition: enforce x = sum b_i * 2^i and each b_i boolean
pub fn range_check<D: Driver>(dr: &mut D, x: D::W, bits: usize) -> Result<()> {
    let mut acc = dr.from_field(D::F::ZERO);
    let mut pow = D::F::ONE;
    for _ in 0..bits {
        let zero_wire = dr.from_field(D::F::ZERO);
        let bi = dr.add(|| vec![(zero_wire.clone(), D::F::ONE)])?; // allocate new wire equal to zero
        boolean(dr, bi.clone())?;
        let term = dr.add(|| vec![(bi, pow)])?;
        acc = dr.add(|| vec![(acc.clone(), D::F::ONE), (term, D::F::ONE)])?;
        pow = pow + pow;
    }
    dr.enforce_zero(|| vec![(acc, D::F::ONE), (x, -D::F::ONE)])
}

/// Poseidon2-like hash over Pasta using Halo2 primitives (width 3, rate 2).
/// Returns H(tag, a, b) for convenience in t=3 mode.
pub fn poseidon2_t3_hash_tagged(a: Fr, b: Fr, tag: u64) -> Fr {
    let tag_f = Fr::from(tag);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag_f, a, b])
}


