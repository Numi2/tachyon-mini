// src/driver.rs
//! Driver-style circuit synthesis with non-uniform support.

use crate::cs::{ConstraintSystem, LinComb, Var};
use ff::PrimeField;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SynthesisError {
    #[error("mismatched instance length")]
    InstanceLength,
    #[error("verification failed")]
    Verification,
}

#[derive(Clone, Debug)]
pub struct Instance<F: PrimeField> {
    /// Ordered public inputs as field elements.
    pub inputs: Vec<F>,
}

pub trait Driver<F: PrimeField> {
    type Var: Copy;

    fn cs(&mut self) -> &mut ConstraintSystem<F>;

    // primitives
    fn input_public(&mut self, value: F) -> Self::Var;
    fn witness(&mut self, value: F) -> Self::Var;
    fn add(&mut self, a: Self::Var, b: Self::Var) -> Self::Var;
    fn mul(&mut self, a: Self::Var, b: Self::Var) -> Self::Var;
    fn enforce_zero(&mut self, lc: LinComb<F>);

    // derived helpers
    fn add_const(&mut self, a: Self::Var, c: F) -> Self::Var;
    fn scale(&mut self, a: Self::Var, s: F) -> Self::Var;

    // finalize
    fn instance(&self) -> Instance<F>;
}

/// CPU driver evaluates witness immediately and records constraints.
pub struct CpuDriver<F: PrimeField> {
    cs: ConstraintSystem<F>,
    values: Vec<F>, // index by Var.0
}

impl<F: PrimeField> CpuDriver<F> {
    pub fn new() -> Self { Self { cs: ConstraintSystem::default(), values: Vec::new() } }

    #[inline]
    fn push_value(&mut self, v: F, public: bool) -> Var {
        let var = if public { self.cs.alloc_public() } else { self.cs.alloc() };
        if var.0 as usize == self.values.len() { self.values.push(v); } else { self.values[var.0 as usize] = v; }
        var
    }

    pub fn value(&self, v: Var) -> F { self.values[v.0 as usize] }
}

impl<F: PrimeField> Driver<F> for CpuDriver<F> {
    type Var = Var;

    fn cs(&mut self) -> &mut ConstraintSystem<F> { &mut self.cs }

    fn input_public(&mut self, value: F) -> Self::Var { self.push_value(value, true) }
    fn witness(&mut self, value: F) -> Self::Var { self.push_value(value, false) }

    fn add(&mut self, a: Self::Var, b: Self::Var) -> Self::Var {
        let va = self.value(a);
        let vb = self.value(b);
        let out = self.witness(va + vb);
        self.enforce_zero(LinComb { terms: vec![(out, F::ONE), (a, -F::ONE), (b, -F::ONE)], constant: F::ZERO });
        out
    }

    fn mul(&mut self, a: Self::Var, b: Self::Var) -> Self::Var {
        let out = self.witness(self.value(a) * self.value(b));
        self.cs().r1cs(
            LinComb { terms: vec![(a, F::ONE)], constant: F::ZERO },
            LinComb { terms: vec![(b, F::ONE)], constant: F::ZERO },
            LinComb { terms: vec![(out, F::ONE)], constant: F::ZERO },
        );
        out
    }

    fn enforce_zero(&mut self, lc: LinComb<F>) { self.cs.enforce_zero(lc); }

    fn add_const(&mut self, a: Self::Var, c: F) -> Self::Var {
        let out = self.witness(self.value(a) + c);
        self.enforce_zero(LinComb { terms: vec![(out, F::ONE), (a, -F::ONE)], constant: -c });
        out
    }

    fn scale(&mut self, a: Self::Var, s: F) -> Self::Var {
        let out = self.witness(self.value(a) * s);
        self.enforce_zero(LinComb { terms: vec![(out, F::ONE), (a, -s)], constant: F::ZERO });
        out
    }

    fn instance(&self) -> Instance<F> {
        let mut inputs = Vec::with_capacity(self.cs.public_inputs.len());
        for &v in &self.cs.public_inputs { inputs.push(self.values[v.0 as usize]); }
        Instance { inputs }
    }
}

/// Input → main → output contract.
pub trait Circuit<F: PrimeField> {
    type Input;
    type Output;

    /// Synthesize into the provided driver. May branch at runtime for non-uniform circuits.
    fn synthesize<D: Driver<F>>(&self, d: &mut D, input: Self::Input) -> Self::Output;
}