// src/cs.rs
// Numan's R1CS implementation
//! 
//! R1CS (Rank-1 Constraint System) - this is the language we use to express circuits!
//! Think of it like writing equations that prove your computation is correct.
//! Each constraint is like saying "A times B equals C" with our secret values.

use ff::PrimeField;

/// A variable in our constraint system - just a unique ID number
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Var(pub u32);

/// A linear combination is like a weighted sum: c₀ + c₁·x₁ + c₂·x₂ + ...
/// We use these to build up our constraints.
#[derive(Clone, Debug)]
pub struct LinComb<F: PrimeField> {
    pub terms: Vec<(Var, F)>,  // Each variable and its coefficient
    pub constant: F,            // The constant term
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

/// A constraint is a rule that our values must satisfy.
/// We have two types: multiplication constraints and equality-to-zero constraints.
#[derive(Clone, Debug)]
pub enum Constraint<F: PrimeField> {
    /// The classic R1CS constraint: A * B = C
    /// This lets us encode multiplication relationships between variables
    R1CS { a: LinComb<F>, b: LinComb<F>, c: LinComb<F> },
    /// A simpler constraint: A = 0
    /// Useful for enforcing that something equals a specific value
    EqZero { a: LinComb<F> },
}

/// The constraint system holds all our variables and rules.
/// It's like a big list of equations that our proof must satisfy.
#[derive(Default)]
pub struct ConstraintSystem<F: PrimeField> {
    pub num_vars: u32,                 // How many variables we have
    pub public_inputs: Vec<Var>,       // Which ones are public (visible to everyone)
    pub constraints: Vec<Constraint<F>>, // All the rules/equations
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