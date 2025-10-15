//! Folding scheme API for recursive accumulation and non-uniform circuits.

use pasta_curves::Fp as Fr;

use crate::accum::{FoldDigest, fold_digests};

/// A transcript-friendly accumulator that can be folded with another instance.
pub trait Foldable {
    /// Digest to be folded/verified at the next layer.
    fn fold_digest(&self) -> FoldDigest;
}

/// A simple fold combiner operating over Pasta fields, intended to be mirrorable
/// inside circuits using the same Poseidon hash function.
#[derive(Clone, Copy, Debug)]
pub struct PoseidonFoldCombiner { pub tag: u64 }

impl Default for PoseidonFoldCombiner { fn default() -> Self { Self { tag: 0xF011D } } }

impl PoseidonFoldCombiner {
    pub fn combine(&self, a: FoldDigest, b: FoldDigest) -> FoldDigest { fold_digests(a, b, self.tag) }
}

/// Folding an arbitrary number of digests using a binary tree.
pub fn fold_many(digests: &[FoldDigest], comb: PoseidonFoldCombiner) -> Option<FoldDigest> {
    if digests.is_empty() { return None; }
    let mut cur: Vec<FoldDigest> = digests.to_vec();
    while cur.len() > 1 {
        let mut next: Vec<FoldDigest> = Vec::with_capacity(cur.len().div_ceil(2));
        for chunk in cur.chunks(2) {
            let d = if chunk.len() == 2 { comb.combine(chunk[0], chunk[1]) } else { chunk[0] };
            next.push(d);
        }
        cur = next;
    }
    cur.first().copied()
}

/// Example foldable structure composed of a running digest and public inputs snapshot.
#[derive(Clone, Debug)]
pub struct FoldState { pub digest: FoldDigest, pub public_inputs: Vec<Fr> }

impl Foldable for FoldState { fn fold_digest(&self) -> FoldDigest { self.digest } }


