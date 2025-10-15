//  accumulation over pasta sausen -  Numan
//! Split accumulation over Pasta scalars.

use ff::PrimeField;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accumulator<F: PrimeField> {
    pub v: F,
}

impl<F: PrimeField> Accumulator<F> {
    pub fn zero() -> Self { Self { v: F::ZERO } }
    pub fn unit(x: F) -> Self { Self { v: x } }
    pub fn merge(self, other: Self) -> Self { Self { v: self.v + other.v } }
}

#[derive(Clone, Debug)]
pub struct SplitAccumulator<F: PrimeField> {
    pub leaves: Vec<Accumulator<F>>,
}

impl<F: PrimeField> SplitAccumulator<F> {
    pub fn new() -> Self { Self { leaves: Vec::new() } }
    pub fn push(&mut self, a: Accumulator<F>) { self.leaves.push(a); }

    pub fn split_fold(&self) -> Accumulator<F> {
        if self.leaves.is_empty() { return Accumulator::zero(); }
        let mut layer = self.leaves.clone();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity((layer.len() + 1) / 2);
            for chunk in layer.chunks(2) {
                let merged = if chunk.len() == 2 { chunk[0].merge(chunk[1]) } else { chunk[0] };
                next.push(merged);
            }
            layer = next;
        }
        layer[0]
    }
}