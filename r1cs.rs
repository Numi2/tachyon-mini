// src/cs.rs
// lowrisk r1cs -  Numan
//!  R1CS-like objects.

use ff::PrimeField;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Var(pub u32);

#[derive(Clone, Debug)]
pub struct LinComb<F: PrimeField> {
    pub terms: Vec<(Var, F)>,
    pub constant: F,
}

impl<F: PrimeField> LinComb<F> {
    pub fn zero() -> Self {
        Self { terms: Vec::new(), constant: F::ZERO }
    }
    pub fn from_var(v: Var) -> Self {
        Self { terms: vec![(v, F::ONE)], constant: F::ZERO }
    }
    pub fn add_term(mut self, v: Var, c: F) -> Self {
        self.terms.push((v, c));
        self
    }
    pub fn add_const(mut self, c: F) -> Self {
        self.constant += c;
        self
    }
}

#[derive(Clone, Debug)]
pub enum Constraint<F: PrimeField> {
    /// <A, X> * <B, X> - <C, X> = 0
    R1CS { a: LinComb<F>, b: LinComb<F>, c: LinComb<F> },
    /// <A, X> = 0
    EqZero { a: LinComb<F> },
}

#[derive(Default)]
pub struct ConstraintSystem<F: PrimeField> {
    pub num_vars: u32,
    pub public_inputs: Vec<Var>,
    pub constraints: Vec<Constraint<F>>,
}

impl<F: PrimeField> ConstraintSystem<F> {
    pub fn alloc(&mut self) -> Var {
        let v = Var(self.num_vars);
        self.num_vars += 1;
        v
    }
    pub fn alloc_public(&mut self) -> Var {
        let v = self.alloc();
        self.public_inputs.push(v);
        v
    }
    pub fn r1cs(&mut self, a: LinComb<F>, b: LinComb<F>, c: LinComb<F>) {
        self.constraints.push(Constraint::R1CS { a, b, c });
    }
    pub fn enforce_zero(&mut self, a: LinComb<F>) {
        self.constraints.push(Constraint::EqZero { a });
    }
}