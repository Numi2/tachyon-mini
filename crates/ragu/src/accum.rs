//! Unified accumulator interfaces and Pasta-oriented instances.
//! The goal is to support both membership and non-membership proofs under a single
//! accumulator abstraction, amenable to folding and recursion.

use ff::Field;
use pasta_curves::Fp as Fr;
use crate::tachygram::Tachygram;

/// A digest of an accumulator state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccumDigest(pub Fr);

/// Unified accumulator item: either a membership witness to an element, or a
/// non-membership witness to absence, with the same interface.
#[derive(Clone, Debug)]
pub enum AccumItem {
    Member(Tachygram),        // a gram inserted (commitment)
    NonMember(Tachygram),     // a gram claimed absent (nullifier)
}

/// Trait for unified accumulators over Pasta fields.
pub trait UnifiedAccumulator {
    /// Return the current accumulator digest.
    fn digest(&self) -> AccumDigest;

    /// Absorb a batch of items (both Member and NonMember). Implementations must
    /// update the digest deterministically.
    fn absorb_all(&mut self, items: &[AccumItem]);
}

/// A simple Poseidon2-based digested accumulator over a sparse set, meant as a
/// placeholder that is recursion/PCD-friendly on Pasta. This is not a cryptographic
/// accumulator with succinct update proofs; instead it defines a unification surface
/// for membership/non-membership items and provides deterministic folding hooks.
#[derive(Clone, Debug)]
pub struct PoseidonUnifiedAccum {
    pub state: Fr,
    pub domain_tag: u64,
}

impl Default for PoseidonUnifiedAccum {
    fn default() -> Self { Self { state: Fr::ZERO, domain_tag: 0 } }
}

impl PoseidonUnifiedAccum {
    pub fn new(tag: u64) -> Self { Self { state: Fr::ZERO, domain_tag: tag } }

    #[inline]
    fn mix(&mut self, kind: u64, value: Fr) {
        let t = crate::gadgets::poseidon2_t3_hash_tagged(self.state, value, self.domain_tag ^ kind);
        self.state = t;
    }
}

impl UnifiedAccumulator for PoseidonUnifiedAccum {
    fn digest(&self) -> AccumDigest { AccumDigest(self.state) }

    fn absorb_all(&mut self, items: &[AccumItem]) {
        for itm in items {
            match itm {
                AccumItem::Member(g) => {
                    if let Some(f) = g.to_field() { self.mix(1, f); }
                }
                AccumItem::NonMember(g) => {
                    if let Some(f) = g.to_field() { self.mix(2, f); }
                }
            }
        }
    }
}

/// A foldable accumulator state used for recursive aggregation. The fold operation
/// combines two accumulator digests into one using a collision-resistant combiner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoldDigest(pub Fr);

/// Combine two digests deterministically using Poseidon2 t=3.
pub fn fold_digests(left: FoldDigest, right: FoldDigest, tag: u64) -> FoldDigest {
    let out = crate::gadgets::poseidon2_t3_hash_tagged(left.0, right.0, tag);
    FoldDigest(out)
}


