//! Backend traits and a mock prover/verifier for R1CS.
//! Numan Thabit 2025
//! This module provides a production-ready API shape with a development/mock backend
//! that serializes R1CS constraints and witness assignments, derives a transcript
//! digest, and verifies constraints in the value domain. A Halo2+KZG backend can
//! implement the same interfaces and replace the mock implementation transparently.

use anyhow::{anyhow, Result};
use ff::{Field, PrimeField};
use serde::{Serialize, Deserialize};

use crate::r1cs::{R1csRecorder, Var, VarKind};
// use crate::circuit::Driver; // no direct trait methods used here

/// Versioned proof format for mock proofs
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProofFormatVersion(pub u8);

/// R1CS mock proof carrying constraints and witness assignments (not ZK).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "F: ff::PrimeField", deserialize = "F: ff::PrimeField"))]
pub struct R1csMockProof<F: Field> {
    pub version: ProofFormatVersion,
    /// Domain separation for the circuit
    pub domain: Vec<u8>,
    /// Digest of constraints (structure-only)
    pub r1cs_digest: [u8; 32],
    /// Serialized constraints (no witness)
    pub constraints_bytes: Vec<u8>,
    /// Public inputs as field elements
    #[serde(with = "crate::r1cs::serde_vec_field_bytes")]
    pub public_inputs: Vec<F>,
    /// Witness assignments for all witness variables
    #[serde(with = "crate::r1cs::serde_vec_field_bytes")]
    pub witness_values: Vec<F>,
}

impl<F: PrimeField> R1csMockProof<F> {
    pub fn to_bytes(&self) -> Result<Vec<u8>> { Ok(bincode::serialize(self)?) }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { Ok(bincode::deserialize(bytes)?) }
}

/// Build a mock proof from a recorder and a list of instance variables in index order.
pub fn prove_mock<F: PrimeField>(
    domain: &[u8],
    recorder: &R1csRecorder<F>,
    instance_vars: &[Var],
) -> Result<R1csMockProof<F>> {
    // Collect public inputs in order
    let mut public_inputs = Vec::with_capacity(instance_vars.len());
    for v in instance_vars {
        match recorder.vars.get(v.0).ok_or_else(|| anyhow!("bad instance var index"))? {
            VarKind::Instance => {
                let val = recorder.get_assignment(*v).ok_or_else(|| anyhow!("missing instance value"))?;
                public_inputs.push(val);
            }
            VarKind::Witness => return Err(anyhow!("instance list includes witness var")),
        }
    }

    // Collect witness values in index order
    let mut witness_values = Vec::new();
    for (i, kind) in recorder.vars.iter().enumerate() {
        if matches!(kind, VarKind::Witness) {
            let v = Var(i);
            let val = recorder.get_assignment(v).ok_or_else(|| anyhow!("missing witness value"))?;
            witness_values.push(val);
        }
    }

    let constraints_bytes = recorder.serialize_constraints();
    let r1cs_digest = recorder.digest(domain);

    Ok(R1csMockProof {
        version: ProofFormatVersion(1),
        domain: domain.to_vec(),
        r1cs_digest,
        constraints_bytes,
        public_inputs,
        witness_values,
    })
}

/// Verify a mock proof by reconstructing the recorder and re-evaluating all constraints.
pub fn verify_mock<F: PrimeField>(
    proof: &R1csMockProof<F>,
) -> Result<bool> {
    let mut rec = R1csRecorder::<F>::deserialize_constraints(&proof.constraints_bytes)?;
    // Check digest first
    let dig = rec.digest(&proof.domain);
    if dig != proof.r1cs_digest { return Ok(false); }

    // Rehydrate assignments
    let mut wit_iter = proof.witness_values.iter();
    for i in 0..rec.vars.len() {
        match rec.vars[i] {
            VarKind::Witness => {
                let val = wit_iter.next().ok_or_else(|| anyhow!("witness length mismatch"))?;
                rec.set_assignment(Var(i), *val);
            }
            VarKind::Instance => { /* verified as public inputs separately; optional */ }
        }
    }
    if wit_iter.next().is_some() { return Err(anyhow!("witness length mismatch (extra)")); }

    // Evaluate each constraint in value domain: <A, x> * <B, x> = <C, x>
    let eval_lc = |lc: &crate::r1cs::LinearCombination<F>, get: &dyn Fn(Var) -> Option<F>| -> Result<F> {
        let mut acc = F::ZERO;
        for t in &lc.terms {
            let v = get(t.var).ok_or_else(|| anyhow!("missing value for var"))?;
            acc += v * t.coeff;
        }
        acc += lc.constant;
        Ok(acc)
    };

    // Use indices to avoid borrowing rec immutably and mutably at the same time
    for idx in 0..rec.constraints.len() {
        let c = &rec.constraints[idx];
        let get = |v: Var| rec.get_assignment(v);
        let a = eval_lc(&c.a, &get)?;
        let b = eval_lc(&c.b, &get)?;
        let c_val = eval_lc(&c.c, &get)?;
        if a * b != c_val { return Ok(false); }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{R1csProverDriver, Wire};
    use crate::circuit::Driver; // bring trait methods (add, mul, enforce_zero) into scope
    type Fr = pasta_curves::Fp;

    #[test]
    fn mock_prove_verify_roundtrip() {
        let mut drv: R1csProverDriver<Fr> = R1csProverDriver::default();
        // Build a small circuit: z = a + 2b, check z - a - 2b == 0, and x = a*b
        let a = drv.add(|| vec![(Wire::Const(Fr::from(3u64)), Fr::ONE)]).unwrap();
        let b = drv.add(|| vec![(Wire::Const(Fr::from(5u64)), Fr::ONE)]).unwrap();
        let two = Fr::from(2u64);
        let z = drv.add(|| vec![(a.clone(), Fr::ONE), (b.clone(), two)]).unwrap();
        drv.enforce_zero(|| vec![(z.clone(), Fr::ONE), (a.clone(), -Fr::ONE), (b.clone(), -two)]).unwrap();
        let _ = drv.mul(|| Ok((Fr::from(3u64), Fr::from(5u64), Fr::from(15u64)))).unwrap();

        // Mark a public instance equal to z
        let inst = drv.r1cs.alloc_instance();
        let z_val = drv.r1cs.get_assignment(match z { Wire::Var(v) => v, _ => panic!() }).unwrap();
        drv.r1cs.set_assignment(inst, z_val);

        let proof = prove_mock::<Fr>(b"test-circuit", &drv.r1cs, &[inst]).unwrap();
        let ok = verify_mock::<Fr>(&proof).unwrap();
        assert!(ok);
    }
}


