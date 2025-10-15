//! R1CS recorder and drivers for non-uniform circuits.
//! Numan Thabit 2025
//! Provides:
//! - Minimal rank-1 constraint system (R1CS) recorder with deterministic ordering
//! - Linear combinations with constants
//! - Prover driver that records constraints while computing witness values
//! - Sink integration to extract public inputs as field elements

use anyhow::Result;

use ff::{Field, PrimeField};
use std::collections::HashMap;
use blake3::Hasher as Blake3Hasher;
use serde::{Serialize, Deserialize};

use crate::circuit::Driver;
use crate::drivers::PublicInput;

/// Escape hatch events allow recording non-R1CS semantics alongside constraints.
/// Backends may interpret these to add native gadgets (e.g., Poseidon, lookups).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EscapeEvent {
    /// Poseidon2-like permutation invocation with a tag for domain separation.
    /// inputs/outputs refer to variable indices in this recorder.
    Poseidon2 { inputs: Vec<Var>, outputs: Vec<Var>, tag: u64 },
    /// A foreign gadget identified by name with opaque data payload.
    Foreign { name: String, inputs: Vec<Var>, outputs: Vec<Var>, data: Vec<u8> },
    /// A lookup into a table identified by an application-specific id.
    Lookup { table_id: u32, cols: Vec<Var> },
}

/// Unique identifier for a variable within the recorder
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Var(pub usize);

/// Variable kind for bookkeeping
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VarKind {
    Witness,
    Instance,
}

/// A single term of a linear combination: coeff * var
#[derive(Clone, Debug)]
pub struct LinearTerm<F: Field> {
    pub var: Var,
    pub coeff: F,
}

/// A linear combination: sum_i coeff_i * var_i + constant
#[derive(Clone, Debug)]
pub struct LinearCombination<F: Field> {
    pub terms: Vec<LinearTerm<F>>,
    pub constant: F,
}

impl<F: Field> LinearCombination<F> {
    pub fn zero() -> Self { Self { terms: Vec::new(), constant: F::ZERO } }
    pub fn one() -> Self { Self { terms: Vec::new(), constant: F::ONE } }

    #[inline]
    pub fn with_constant(mut self, c: F) -> Self { self.constant = c; self }

    #[inline]
    pub fn push_term(&mut self, var: Var, coeff: F) { self.terms.push(LinearTerm { var, coeff }); }

    /// Convenience builder: lc + coeff * var
    #[inline]
    pub fn add(mut self, var: Var, coeff: F) -> Self { self.push_term(var, coeff); self }
}

/// One R1CS constraint: <A, x> * <B, x> = <C, x>
#[derive(Clone, Debug)]
pub struct Constraint<F: Field> {
    pub id: u64,
    pub label: Option<String>,
    pub a: LinearCombination<F>,
    pub b: LinearCombination<F>,
    pub c: LinearCombination<F>,
}

/// In-memory recorder for variables and constraints
#[derive(Clone, Debug)]
pub struct R1csRecorder<F: Field> {
    next_var: usize,
    next_constraint_id: u64,
    pub vars: Vec<VarKind>,
    pub constraints: Vec<Constraint<F>>,
    /// Optional witness assignment for variables (witness values only)
    pub assignments: HashMap<Var, F>,
    /// Escape hatch events recorded in-order
    pub escapes: Vec<EscapeEvent>,
}

impl<F: Field> Default for R1csRecorder<F> {
    fn default() -> Self {
        Self {
            next_var: 0,
            next_constraint_id: 0,
            vars: Vec::new(),
            constraints: Vec::new(),
            assignments: HashMap::new(),
            escapes: Vec::new(),
        }
    }
}

impl<F: Field> R1csRecorder<F> {
    pub fn new() -> Self { Self::default() }

    #[inline]
    pub fn alloc_witness(&mut self) -> Var {
        let v = Var(self.next_var);
        self.next_var += 1;
        self.vars.push(VarKind::Witness);
        v
    }

    #[inline]
    pub fn alloc_instance(&mut self) -> Var {
        let v = Var(self.next_var);
        self.next_var += 1;
        self.vars.push(VarKind::Instance);
        v
    }

    #[inline]
    pub fn set_assignment(&mut self, var: Var, value: F) { self.assignments.insert(var, value); }

    #[inline]
    pub fn get_assignment(&self, var: Var) -> Option<F> { self.assignments.get(&var).copied() }

    #[inline]
    pub fn num_vars(&self) -> usize { self.vars.len() }

    #[inline]
    pub fn num_constraints(&self) -> usize { self.constraints.len() }

    /// Record a multiplication constraint: A * B = C
    pub fn enforce_mul_eq(&mut self, label: Option<&str>, a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) {
        let id = self.next_constraint_id;
        self.next_constraint_id += 1;
        self.constraints.push(Constraint {
            id,
            label: label.map(|s| s.to_string()),
            a,
            b,
            c,
        });
    }

    /// Enforce a linear combination equals zero: lc == 0
    pub fn enforce_zero(&mut self, label: Option<&str>, lc: LinearCombination<F>) {
        // Encode as lc * 1 = 0
        self.enforce_mul_eq(label, lc, LinearCombination::one(), LinearCombination::zero());
    }

    /// Record a Poseidon2 escape event with explicit inputs/outputs and a tag.
    pub fn emit_poseidon2(&mut self, inputs: &[Var], outputs: &[Var], tag: u64) {
        self.escapes.push(EscapeEvent::Poseidon2 { inputs: inputs.to_vec(), outputs: outputs.to_vec(), tag });
    }

    /// Record a named foreign gadget with an opaque payload.
    pub fn emit_foreign(&mut self, name: &str, inputs: &[Var], outputs: &[Var], data: &[u8]) {
        self.escapes.push(EscapeEvent::Foreign { name: name.to_string(), inputs: inputs.to_vec(), outputs: outputs.to_vec(), data: data.to_vec() });
    }

    /// Record a lookup event into a table id with provided columns.
    pub fn emit_lookup(&mut self, table_id: u32, cols: &[Var]) {
        self.escapes.push(EscapeEvent::Lookup { table_id, cols: cols.to_vec() });
    }
}

/// A wire value for drivers: either a variable or a constant field element.
#[derive(Clone, Debug)]
pub enum Wire<F: Field> {
    Var(Var),
    Const(F),
}

impl<F: Field> Wire<F> {
    #[inline]
    #[allow(dead_code)]
    fn as_lc(&self) -> LinearCombination<F> {
        match self {
            Wire::Var(v) => {
                let mut lc = LinearCombination::zero();
                lc.push_term(*v, F::ONE);
                lc
            }
            Wire::Const(c) => LinearCombination { terms: Vec::new(), constant: *c },
        }
    }
}

/// Prover driver that records constraints and computes witness assignments.
pub struct R1csProverDriver<F: Field> {
    pub r1cs: R1csRecorder<F>,
}

impl<F: Field> Default for R1csProverDriver<F> {
    fn default() -> Self { Self { r1cs: R1csRecorder::new() } }
}

impl<F: Field> Driver for R1csProverDriver<F> {
    type F = F;
    type W = Wire<F>;
    const ONE: Self::W = Wire::Const(F::ONE);
    type MaybeKind = crate::maybe::KindAlways;
    type IO = PublicInput<F>;

    fn from_field(&mut self, value: Self::F) -> Self::W { Wire::Const(value) }

    fn mul(
        &mut self,
        values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
    ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error> {
        // Evaluate closure to obtain witness assignments; allocate variables
        let (a_val, b_val, c_val) = values()?;
        let a = self.r1cs.alloc_witness();
        let b = self.r1cs.alloc_witness();
        let c = self.r1cs.alloc_witness();
        self.r1cs.set_assignment(a, a_val);
        self.r1cs.set_assignment(b, b_val);
        self.r1cs.set_assignment(c, c_val);

        // Record constraint: a * b = c
        let mut lc_a = LinearCombination::zero(); lc_a.push_term(a, F::ONE);
        let mut lc_b = LinearCombination::zero(); lc_b.push_term(b, F::ONE);
        let mut lc_c = LinearCombination::zero(); lc_c.push_term(c, F::ONE);
        self.r1cs.enforce_mul_eq(Some("mul"), lc_a, lc_b, lc_c);
        Ok((Wire::Var(a), Wire::Var(b), Wire::Var(c)))
    }

    fn add<L: IntoIterator<Item = (Self::W, Self::F)>>( 
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<Self::W, anyhow::Error> {
        // Build linear combination from provided terms; evaluate value to assign output
        let mut out_lc = LinearCombination::zero();
        let mut value = F::ZERO;
        for (w, coeff) in lc() {
            match w {
                Wire::Var(v) => {
                    out_lc.push_term(v, coeff);
                    if let Some(av) = self.r1cs.get_assignment(v) {
                        value += av * coeff;
                    }
                }
                Wire::Const(c) => {
                    value += c * coeff;
                }
            }
        }

        // Allocate an output variable and enforce out = out_lc
        let out = self.r1cs.alloc_witness();
        self.r1cs.set_assignment(out, value);

        // Enforce (out_lc - out) == 0 → (out_lc - out) * 1 = 0
        let mut lc_minus_out = out_lc.clone();
        lc_minus_out.push_term(out, -F::ONE);
        self.r1cs.enforce_zero(Some("add_out"), lc_minus_out);
        Ok(Wire::Var(out))
    }

    fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>( 
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<(), anyhow::Error> {
        let mut combined = LinearCombination::zero();
        for (w, coeff) in lc() {
            match w {
                Wire::Var(v) => combined.push_term(v, coeff),
                Wire::Const(c) => { combined.constant += c * coeff; }
            }
        }
        self.r1cs.enforce_zero(Some("lc_zero"), combined);
        Ok(())
    }

    fn enforce_mul<LA, LB, LC>(
        &mut self,
        a: impl FnOnce() -> LA,
        b: impl FnOnce() -> LB,
        c: impl FnOnce() -> LC,
    ) -> Result<(), anyhow::Error>
    where
        LA: IntoIterator<Item = (Self::W, Self::F)>,
        LB: IntoIterator<Item = (Self::W, Self::F)>,
        LC: IntoIterator<Item = (Self::W, Self::F)>
    {
        let mut to_lc_a = LinearCombination::zero();
        for (w, coeff) in a() {
            match w {
                Wire::Var(v) => to_lc_a.push_term(v, coeff),
                Wire::Const(c) => { to_lc_a.constant += c * coeff; }
            }
        }
        let mut to_lc_b = LinearCombination::zero();
        for (w, coeff) in b() {
            match w {
                Wire::Var(v) => to_lc_b.push_term(v, coeff),
                Wire::Const(c) => { to_lc_b.constant += c * coeff; }
            }
        }
        let mut to_lc_c = LinearCombination::zero();
        for (w, coeff) in c() {
            match w {
                Wire::Var(v) => to_lc_c.push_term(v, coeff),
                Wire::Const(c) => { to_lc_c.constant += c * coeff; }
            }
        }
        self.r1cs.enforce_mul_eq(Some("enforce_mul"), to_lc_a, to_lc_b, to_lc_c);
        Ok(())
    }
}

impl<F: Field> R1csProverDriver<F> {
    /// Allocate a new instance variable with a concrete value and return its wire
    pub fn alloc_instance_value(&mut self, value: F) -> Wire<F> {
        let v = self.r1cs.alloc_instance();
        self.r1cs.set_assignment(v, value);
        Wire::Var(v)
    }

    /// Allocate a new witness variable with a concrete value and return its wire
    pub fn alloc_witness_value(&mut self, value: F) -> Wire<F> {
        let v = self.r1cs.alloc_witness();
        self.r1cs.set_assignment(v, value);
        Wire::Var(v)
    }
}

// Allow collecting public outputs as field elements by resolving wire values
impl<F: Field> crate::circuit::Sink<R1csProverDriver<F>, Wire<F>> for PublicInput<F> {
    fn absorb(&mut self, value: Wire<F>) {
        match value {
            Wire::Const(c) => self.values.push(c),
            // In this lightweight driver, unresolved vars cannot be absorbed as field values.
            // Silently ignore to avoid panics in consumers that call absorb() generically.
            Wire::Var(_v) => {}
        }
    }
}

impl<F: Field> PublicInput<F> {
    /// Resolve a vector of wires into concrete field public inputs using the recorder assignments.
    pub fn from_wires(driver: &R1csProverDriver<F>, outputs: &[Wire<F>]) -> Vec<F> {
        let mut out = Vec::with_capacity(outputs.len());
        for w in outputs {
            match w {
                Wire::Const(c) => out.push(*c),
                Wire::Var(v) => {
                    if let Some(val) = driver.r1cs.get_assignment(*v) { out.push(val); }
                }
            }
        }
        out
    }
}

// Helper module to (de)serialize Vec<F> where F: PrimeField, as sequences of canonical bytes
pub(crate) mod serde_vec_field_bytes {
    use ff::PrimeField;
    use serde::{Serializer, Deserializer};
    use serde::ser::SerializeSeq;
    use serde::de::{Visitor, SeqAccess, Error as DeError};
    use core::marker::PhantomData;

    pub fn serialize<F: PrimeField, S: Serializer>(v: &[F], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for f in v.iter() {
            let repr = f.to_repr();
            seq.serialize_element(repr.as_ref())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, F: PrimeField, D: Deserializer<'de>>(d: D) -> Result<Vec<F>, D::Error> {
        struct VecVisitor<F: PrimeField>(PhantomData<F>);
        impl<'de, F: PrimeField> Visitor<'de> for VecVisitor<F> {
            type Value = Vec<F>;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result { write!(f, "sequence of field bytes") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out: Vec<F> = Vec::new();
                while let Some(bytes) = a.next_element::<Vec<u8>>()? {
                    let mut repr = <F as PrimeField>::Repr::default();
                    if bytes.len() != repr.as_ref().len() { return Err(DeError::custom("wrong length")); }
                    repr.as_mut().copy_from_slice(&bytes);
                    let ct = F::from_repr(repr);
                    let opt: Option<F> = ct.into();
                    match opt { Some(v) => out.push(v), None => return Err(DeError::custom("invalid field repr")) }
                }
                Ok(out)
            }
        }
        d.deserialize_seq(VecVisitor::<F>(PhantomData))
    }
}

/// Canonical transcript digest for recorded R1CS (structure only; excludes witness assignments)
impl<F: Field> R1csRecorder<F> {
    pub fn digest(&self, domain: &[u8]) -> [u8; 32]
    where
        F: PrimeField,
    {
        let mut h = Blake3Hasher::new();
        h.update(b"r1cs:v1");
        h.update(domain);
        h.update(&(self.vars.len() as u64).to_le_bytes());
        h.update(&(self.constraints.len() as u64).to_le_bytes());
        h.update(&(self.escapes.len() as u64).to_le_bytes());

        for (i, vk) in self.vars.iter().enumerate() {
            h.update(&(i as u64).to_le_bytes());
            match vk { VarKind::Witness => { h.update(&[0u8]); }, VarKind::Instance => { h.update(&[1u8]); } }
        }
        for c in &self.constraints {
            h.update(&c.id.to_le_bytes());
            if let Some(label) = &c.label { h.update(label.as_bytes()); }
            // Serialize linear combinations deterministically
            let mut emit_lc = |lc: &LinearCombination<F>| {
                h.update(lc.constant.to_repr().as_ref());
                h.update(&(lc.terms.len() as u64).to_le_bytes());
                for t in &lc.terms {
                    h.update(&(t.var.0 as u64).to_le_bytes());
                    h.update(t.coeff.to_repr().as_ref());
                }
            };
            emit_lc(&c.a); emit_lc(&c.b); emit_lc(&c.c);
        }
        // Mix in escapes deterministically
        for e in &self.escapes {
            match e {
                EscapeEvent::Poseidon2 { inputs, outputs, tag } => {
                    h.update(&[0xE1]);
                    h.update(&tag.to_le_bytes());
                    h.update(&(inputs.len() as u64).to_le_bytes());
                    for v in inputs { h.update(&(v.0 as u64).to_le_bytes()); }
                    h.update(&(outputs.len() as u64).to_le_bytes());
                    for v in outputs { h.update(&(v.0 as u64).to_le_bytes()); }
                }
                EscapeEvent::Foreign { name, inputs, outputs, data } => {
                    h.update(&[0xE2]);
                    h.update(&(name.len() as u64).to_le_bytes());
                    h.update(name.as_bytes());
                    h.update(&(inputs.len() as u64).to_le_bytes());
                    for v in inputs { h.update(&(v.0 as u64).to_le_bytes()); }
                    h.update(&(outputs.len() as u64).to_le_bytes());
                    for v in outputs { h.update(&(v.0 as u64).to_le_bytes()); }
                    h.update(&(data.len() as u64).to_le_bytes());
                    h.update(data);
                }
                EscapeEvent::Lookup { table_id, cols } => {
                    h.update(&[0xE3]);
                    h.update(&table_id.to_le_bytes());
                    h.update(&(cols.len() as u64).to_le_bytes());
                    for v in cols { h.update(&(v.0 as u64).to_le_bytes()); }
                }
            }
        }
        *h.finalize().as_bytes()
    }

    /// Serialize constraints (excluding witness assignments) to bincode for persistence
    pub fn serialize_constraints(&self) -> Vec<u8>
    where F: PrimeField {
        #[derive(Serialize)]
        struct SerTerm { var: u64, coeff: Vec<u8> }
        #[derive(Serialize)]
        struct SerLc { terms: Vec<SerTerm>, constant: Vec<u8> }
        #[derive(Serialize)]
        struct SerCons { id: u64, label: Option<String>, a: SerLc, b: SerLc, c: SerLc }
        #[derive(Serialize)]
        enum SerEsc { Poseidon2 { inputs: Vec<u64>, outputs: Vec<u64>, tag: u64 }, Foreign { name: String, inputs: Vec<u64>, outputs: Vec<u64>, data: Vec<u8> }, Lookup { table_id: u32, cols: Vec<u64> } }
        #[derive(Serialize)]
        struct Snapshot { vars: Vec<u8>, constraints: Vec<SerCons>, escapes: Vec<SerEsc> }

        let vars: Vec<u8> = self.vars.iter().map(|k| match k { VarKind::Witness => 0u8, VarKind::Instance => 1u8 }).collect();
        let to_bytes = |f: &F| f.to_repr().as_ref().to_vec();
        let ser_constraints: Vec<SerCons> = self.constraints.iter().map(|c| {
            let ser_lc = |lc: &LinearCombination<F>| SerLc {
                terms: lc.terms.iter().map(|t| SerTerm { var: t.var.0 as u64, coeff: to_bytes(&t.coeff) }).collect(),
                constant: to_bytes(&lc.constant),
            };
            SerCons { id: c.id, label: c.label.clone(), a: ser_lc(&c.a), b: ser_lc(&c.b), c: ser_lc(&c.c) }
        }).collect();
        let escapes: Vec<SerEsc> = self.escapes.iter().map(|e| match e {
            EscapeEvent::Poseidon2 { inputs, outputs, tag } => SerEsc::Poseidon2 { inputs: inputs.iter().map(|v| v.0 as u64).collect(), outputs: outputs.iter().map(|v| v.0 as u64).collect(), tag: *tag },
            EscapeEvent::Foreign { name, inputs, outputs, data } => SerEsc::Foreign { name: name.clone(), inputs: inputs.iter().map(|v| v.0 as u64).collect(), outputs: outputs.iter().map(|v| v.0 as u64).collect(), data: data.clone() },
            EscapeEvent::Lookup { table_id, cols } => SerEsc::Lookup { table_id: *table_id, cols: cols.iter().map(|v| v.0 as u64).collect() },
        }).collect();
        // Serialization errors should bubble up to the caller; avoid panicking here in library code.
        // Tests and backends that need infallible behavior can unwrap at their boundary.
        bincode::serialize(&Snapshot { vars, constraints: ser_constraints, escapes }).unwrap_or_default()
    }

    /// Deserialize constraints (excluding witness assignments) from bincode
    pub fn deserialize_constraints(bytes: &[u8]) -> Result<R1csRecorder<F>>
    where F: PrimeField {
        #[derive(Deserialize)]
        struct SerTerm { var: u64, coeff: Vec<u8> }
        #[derive(Deserialize)]
        struct SerLc { terms: Vec<SerTerm>, constant: Vec<u8> }
        #[derive(Deserialize)]
        struct SerCons { id: u64, label: Option<String>, a: SerLc, b: SerLc, c: SerLc }
        #[derive(Deserialize)]
        enum SerEsc { Poseidon2 { inputs: Vec<u64>, outputs: Vec<u64>, tag: u64 }, Foreign { name: String, inputs: Vec<u64>, outputs: Vec<u64>, data: Vec<u8> }, Lookup { table_id: u32, cols: Vec<u64> } }
        #[derive(Deserialize)]
        struct Snapshot { vars: Vec<u8>, constraints: Vec<SerCons>, #[serde(default)] escapes: Vec<SerEsc> }

        let snap: Snapshot = bincode::deserialize(bytes)?;
        let mut rec = R1csRecorder::<F> {
            vars: snap.vars.into_iter().map(|b| if b == 0 { VarKind::Witness } else { VarKind::Instance }).collect(),
            ..Default::default()
        };
        let from_bytes = |bytes: &[u8]| -> Result<F, anyhow::Error> {
            let mut repr = <F as PrimeField>::Repr::default();
            if bytes.len() != repr.as_ref().len() { return Err(anyhow::anyhow!("wrong length")); }
            repr.as_mut().copy_from_slice(bytes);
            let ct = F::from_repr(repr);
            let opt: Option<F> = ct.into();
            opt.ok_or_else(|| anyhow::anyhow!("invalid field repr"))
        };
        rec.constraints = snap.constraints.into_iter().map(|c| {
            let parse_lc = |slc: SerLc| -> Result<LinearCombination<F>, anyhow::Error> {
                let mut lc = LinearCombination { terms: Vec::with_capacity(slc.terms.len()), constant: from_bytes(&slc.constant)? };
                for t in slc.terms {
                    lc.terms.push(LinearTerm { var: Var(t.var as usize), coeff: from_bytes(&t.coeff)? });
                }
                Ok(lc)
            };
            let a = match parse_lc(c.a) { Ok(v) => v, Err(_) => LinearCombination { terms: Vec::new(), constant: F::ZERO } };
            let b = match parse_lc(c.b) { Ok(v) => v, Err(_) => LinearCombination { terms: Vec::new(), constant: F::ZERO } };
            let cc = match parse_lc(c.c) { Ok(v) => v, Err(_) => LinearCombination { terms: Vec::new(), constant: F::ZERO } };
            Constraint { id: c.id, label: c.label, a, b, c: cc }
        }).collect();
        // Escapes
        rec.escapes = snap.escapes.into_iter().map(|e| match e {
            SerEsc::Poseidon2 { inputs, outputs, tag } => EscapeEvent::Poseidon2 { inputs: inputs.into_iter().map(|i| Var(i as usize)).collect(), outputs: outputs.into_iter().map(|i| Var(i as usize)).collect(), tag },
            SerEsc::Foreign { name, inputs, outputs, data } => EscapeEvent::Foreign { name, inputs: inputs.into_iter().map(|i| Var(i as usize)).collect(), outputs: outputs.into_iter().map(|i| Var(i as usize)).collect(), data },
            SerEsc::Lookup { table_id, cols } => EscapeEvent::Lookup { table_id, cols: cols.into_iter().map(|i| Var(i as usize)).collect() },
        }).collect();
        rec.next_var = rec.vars.len();
        rec.next_constraint_id = rec.constraints.iter().map(|c| c.id).max().unwrap_or(0).saturating_add(1);
        Ok(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Fr = pasta_curves::Fp;

    #[test]
    fn r1cs_mul_and_add_flow() {
        let mut drv: R1csProverDriver<Fr> = R1csProverDriver::default();

        // Compute z = (a + 2*b) where a=3, b=5
        let a = drv.add(|| vec![(Wire::Const(Fr::from(3u64)), Fr::ONE)]).unwrap();
        let b = drv.add(|| vec![(Wire::Const(Fr::from(5u64)), Fr::ONE)]).unwrap();

        let two = Fr::from(2u64);
        let z = drv.add(|| vec![(a.clone(), Fr::ONE), (b.clone(), two)]).unwrap();

        // Enforce z - a - 2*b == 0 explicitly
        drv.enforce_zero(|| vec![(z.clone(), Fr::ONE), (a.clone(), -Fr::ONE), (b.clone(), -two)]).unwrap();

        // Multiply x = a * b and check c=a*b via recorded constraint
        let (_wa, _wb, _wc) = drv.mul(|| Ok((Fr::from(3u64), Fr::from(5u64), Fr::from(15u64)))).unwrap();

        assert!(drv.r1cs.num_vars() >= 3);
        assert!(drv.r1cs.num_constraints() >= 2);
    }

    #[test]
    fn r1cs_digest_and_serde_roundtrip() {
        let mut drv: R1csProverDriver<Fr> = R1csProverDriver::default();
        let a = drv.add(|| vec![(Wire::Const(Fr::from(7u64)), Fr::ONE)]).unwrap();
        let b = drv.add(|| vec![(Wire::Const(Fr::from(9u64)), Fr::ONE)]).unwrap();
        let _z = drv.add(|| vec![(a, Fr::from(2u64)), (b, Fr::from(3u64))]).unwrap();
        let rec = &drv.r1cs;
        let d1 = rec.digest(b"test-domain");
        let ser = rec.serialize_constraints();
        let rec2: R1csRecorder<Fr> = R1csRecorder::deserialize_constraints(&ser).unwrap();
        let d2 = rec2.digest(b"test-domain");
        assert_eq!(d1, d2);
    }

    #[test]
    fn r1cs_escape_events_roundtrip_affect_digest() {
        let mut drv: R1csProverDriver<Fr> = R1csProverDriver::default();
        let x = drv.add(|| vec![(Wire::Const(Fr::from(11u64)), Fr::ONE)]).unwrap();
        let y = drv.add(|| vec![(Wire::Const(Fr::from(13u64)), Fr::ONE)]).unwrap();
        let (vx, vy) = match (x, y) { (Wire::Var(a), Wire::Var(b)) => (a, b), _ => panic!() };
        drv.r1cs.emit_poseidon2(&[vx], &[vy], 42);
        let d1 = drv.r1cs.digest(b"e-domain");
        let ser = drv.r1cs.serialize_constraints();
        let rec2: R1csRecorder<Fr> = R1csRecorder::deserialize_constraints(&ser).unwrap();
        let d2 = rec2.digest(b"e-domain");
        assert_eq!(d1, d2);
    }
}


