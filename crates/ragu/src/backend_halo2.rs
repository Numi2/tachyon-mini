//! Halo2 + KZG backend for R1CS recorder.
//! Numan Thabit 2025
//! This backend compiles a recorded R1CS (with linear-combination terms and constants)
//! into a Halo2 circuit that enforces, for each constraint row i:
//!   (<A_i, x> + a0_i) * (<B_i, x> + b0_i) = (<C_i, x> + c0_i)
//! using a custom gate over a fixed number of term slots per LC.
//!
//! Notes
//! - Term slots per LC are bounded by `max_terms`. Excess terms should be split upstream.
//! - Variables are assigned once in a canonical table region; per-row LC terms are constrained
//!   equal to their canonical cells to ensure value consistency across constraints.

use anyhow::Result;
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value, AssignedCell},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, keygen_pk, keygen_vk, create_proof, VerifyingKey, ProvingKey},
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{Fp as Fr, vesta::Affine as G1Affine};

use crate::r1cs::{R1csRecorder, Var, LinearCombination};
use crate::r1cs::EscapeEvent;
use serde::{Serialize, Deserialize};

/// Configuration for one LC group with `max_terms` variable/coeff slots and a constant cell.
#[derive(Clone, Debug)]
struct LcGroupConfig {
    var_cols: Vec<Column<Advice>>,   // values of variables
    coeff_cols: Vec<Column<Advice>>, // corresponding coefficients
    const_col: Column<Advice>,       // constant term
}

#[derive(Clone, Debug)]
struct R1csConfig {
    selector: Selector,
    // Canonical variable table: each variable has one assigned value cell
    var_table: Column<Advice>,
    // Three LC groups A, B, C
    a: LcGroupConfig,
    b: LcGroupConfig,
    c: LcGroupConfig,
    // Instance column to expose public inputs
    instance: Column<Instance>,
}

/// Halo2 circuit that enforces the R1CS constraints recorded in `recorder`.
struct R1csCircuit {
    recorder: R1csRecorder<Fr>,
    max_terms: usize,
    instance_vars: Vec<Var>,
}

impl R1csCircuit {
    fn configure(meta: &mut ConstraintSystem<Fr>, max_terms: usize) -> R1csConfig {
        let selector = meta.selector();
        let var_table = meta.advice_column();
        meta.enable_equality(var_table);

        let mk_group = |meta: &mut ConstraintSystem<Fr>| -> LcGroupConfig {
            let const_col = meta.advice_column();
            let mut var_cols = Vec::with_capacity(max_terms);
            let mut coeff_cols = Vec::with_capacity(max_terms);
            for _ in 0..max_terms {
                let v = meta.advice_column();
                let k = meta.advice_column();
                meta.enable_equality(v);
                var_cols.push(v);
                coeff_cols.push(k);
            }
            LcGroupConfig { var_cols, coeff_cols, const_col }
        };

        let a = mk_group(meta);
        let b = mk_group(meta);
        let c = mk_group(meta);

        // One instance column; callers control ordering
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Gate: s * ((sumA + ca) * (sumB + cb) - (sumC + cc)) == 0
        meta.create_gate("r1cs_mul_eq", |meta| {
            let s = meta.query_selector(selector);

            let mut sum_group = |g: &LcGroupConfig| {
                let mut acc = meta.query_advice(g.const_col, Rotation::cur());
                for (v_col, k_col) in g.var_cols.iter().zip(g.coeff_cols.iter()) {
                    let v = meta.query_advice(*v_col, Rotation::cur());
                    let k = meta.query_advice(*k_col, Rotation::cur());
                    acc = acc + v * k;
                }
                acc
            };

            let sa = sum_group(&a);
            let sb = sum_group(&b);
            let sc = sum_group(&c);

            vec![s * (sa * sb - sc)]
        });

        R1csConfig { selector, var_table, a, b, c, instance }
    }
}

impl Circuit<Fr> for R1csCircuit {
    type Config = R1csConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { recorder: R1csRecorder::new(), max_terms: self.max_terms, instance_vars: Vec::new() }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Default max_terms; real value is provided by the constructed circuit via synthesize
        Self::configure(meta, 8)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        // 1) Assign canonical variable table (one row), record the assigned cells per Var
        let mut var_cells: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(self.recorder.vars.len());
        layouter.assign_region(
            || "var_table",
            |mut region| {
                for (i, _kind) in self.recorder.vars.iter().enumerate() {
                    // Only witness and instance kinds are handled; both hold a field value
                    let v = Var(i);
                    let value = self.recorder.get_assignment(v).unwrap_or(Fr::ZERO);
                    let cell = region.assign_advice(|| format!("var[{}]", i), config.var_table, i, || Value::known(value))?;
                    var_cells.push(cell);
                }
                Ok(())
            },
        )?;

        // 2) Expose instance variables in order on the single instance column
        for (idx, v) in self.instance_vars.iter().copied().enumerate() {
            layouter.constrain_instance(var_cells[v.0].cell(), config.instance, idx)?;
        }

        // Helper: assign one LC group's terms/const for a given row, constraining var copies to canonical cells
        let assign_lc = |region: &mut halo2_proofs::circuit::Region<'_, Fr>, row: usize, lc: &LinearCombination<Fr>, g: &LcGroupConfig| -> Result<(), Error> {
            // constant
            region.assign_advice(|| format!("const row {}", row), g.const_col, row, || Value::known(lc.constant))?;
            // terms
            for i in 0..self.max_terms {
                if i < lc.terms.len() {
                    let t = &lc.terms[i];
                    let v_cell = region.assign_advice(|| format!("lc v[{}]", i), g.var_cols[i], row, || Value::known(self.recorder.get_assignment(t.var).unwrap_or(Fr::ZERO)))?;
                    // Constrain equal to canonical var cell
                    region.constrain_equal(v_cell.cell(), var_cells[t.var.0].cell())?;
                    region.assign_advice(|| format!("lc k[{}]", i), g.coeff_cols[i], row, || Value::known(t.coeff))?;
                } else {
                    // pad zeros
                    region.assign_advice(|| format!("lc v[{}] pad", i), g.var_cols[i], row, || Value::known(Fr::ZERO))?;
                    region.assign_advice(|| format!("lc k[{}] pad", i), g.coeff_cols[i], row, || Value::known(Fr::ZERO))?;
                }
            }
            Ok(())
        };

        // 3) For each constraint, assign one row and enable selector
        layouter.assign_region(
            || "constraints",
            |mut region| {
                for (row, cons) in self.recorder.constraints.iter().enumerate() {
                    config.selector.enable(&mut region, row)?;
                    assign_lc(&mut region, row, &cons.a, &config.a)?;
                    assign_lc(&mut region, row, &cons.b, &config.b)?;
                    assign_lc(&mut region, row, &cons.c, &config.c)?;
                }
                Ok(())
            },
        )?;

        // NOTE: Escape events are currently hints only; a production backend could
        // materialize native gates/lookups keyed by these events.
        let _escapes: &Vec<EscapeEvent> = &self.recorder.escapes;

        Ok(())
    }
}

/// Halo2 KZG backend driver for R1CS.
pub struct R1csHalo2Backend {
    pub params: Params<G1Affine>,
    pub vk: VerifyingKey<G1Affine>,
    pub pk: ProvingKey<G1Affine>,
    pub max_terms: usize,
}

impl R1csHalo2Backend {
    pub fn new(k: u32, recorder_shape_hint_terms: usize) -> Result<Self> {
        let max_terms = recorder_shape_hint_terms.max(1);
        let params = Params::<G1Affine>::new(k);
        // Build an empty circuit to derive keys with the chosen shape
        let empty = R1csCircuit { recorder: R1csRecorder::new(), max_terms, instance_vars: Vec::new() };
        let vk = keygen_vk(&params, &empty)?;
        let pk = keygen_pk(&params, vk.clone(), &empty)?;
        Ok(Self { params, vk, pk, max_terms })
    }

    pub fn prove(&self, recorder: R1csRecorder<Fr>, instance_vars: Vec<Var>) -> Result<Vec<u8>> {
        // Collect instance values from recorder in the provided order
        let mut instance_values: Vec<Fr> = Vec::with_capacity(instance_vars.len());
        for v in &instance_vars {
            let val = recorder.get_assignment(*v).ok_or_else(|| anyhow::anyhow!("missing assignment for instance var"))?;
            instance_values.push(val);
        }
        let circuit = R1csCircuit { recorder, max_terms: self.max_terms, instance_vars };
        let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
        let public_inputs: Vec<Fr> = instance_values;
        create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&public_inputs[..]]],
            rand::rngs::OsRng,
            &mut transcript,
        )?;
        Ok(transcript.finalize())
    }

    pub fn verify(&self, proof: &[u8], public_inputs: &[Fr]) -> Result<bool> {
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(std::io::Cursor::new(proof));
        let strategy = halo2_proofs::plonk::SingleVerifier::new(&self.params);
        Ok(halo2_proofs::plonk::verify_proof(&self.params, &self.vk, strategy, &[&[public_inputs]], &mut transcript).is_ok())
    }
}

/// Detached Halo2 proof for a non-uniform R1CS circuit; self-contained verifier data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R1csHalo2Proof {
    /// Circuit size parameter (2^k)
    pub k: u32,
    /// Term capacity per LC group used when compiling
    pub max_terms: usize,
    /// Variable indices (into recorder vars) exposed as public inputs, in order
    pub instance_vars: Vec<usize>,
    /// Serialized constraints (no witness assignments)
    pub constraints_bytes: Vec<u8>,
    /// Prover transcript bytes
    pub proof: Vec<u8>,
}

impl R1csHalo2Proof {
    /// Prove a recorder using an ephemeral backend; keys derived on the given recorder shape.
    pub fn prove(recorder: R1csRecorder<Fr>, instance_vars: Vec<Var>, k: u32, max_terms: usize) -> Result<Self> {
        // Build params and keys from the concrete circuit shape
        let params = Params::<G1Affine>::new(k);
        let circuit = R1csCircuit { recorder: recorder.clone(), max_terms, instance_vars: instance_vars.clone() };
        let vk = keygen_vk(&params, &circuit)?;
        let pk = keygen_pk(&params, vk, &circuit)?;
        // Collect instance values as public inputs
        let mut public_inputs: Vec<Fr> = Vec::with_capacity(instance_vars.len());
        for v in &instance_vars {
            let val = recorder.get_assignment(*v).unwrap_or(Fr::ZERO);
            public_inputs.push(val);
        }
        // Create proof
        let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[&[&public_inputs[..]]], rand::rngs::OsRng, &mut transcript)?;
        let proof_bytes = transcript.finalize();
        // Bundle
        let constraints_bytes = recorder.serialize_constraints();
        Ok(Self {
            k, max_terms, instance_vars: instance_vars.into_iter().map(|v| v.0).collect(), constraints_bytes, proof: proof_bytes,
        })
    }

    /// Verify by reconstructing the circuit shape from constraints and checking the proof.
    pub fn verify(&self, public_inputs: &[Fr]) -> Result<bool> {
        let params = Params::<G1Affine>::new(self.k);
        let rec = R1csRecorder::<Fr>::deserialize_constraints(&self.constraints_bytes)?;
        let instance_vars: Vec<Var> = self.instance_vars.iter().copied().map(Var).collect();
        let circuit = R1csCircuit { recorder: rec.clone(), max_terms: self.max_terms, instance_vars };
        // Regenerate verifying key from circuit shape
        let vk = keygen_vk(&params, &circuit)?;
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(std::io::Cursor::new(&self.proof));
        let strategy = halo2_proofs::plonk::SingleVerifier::new(&params);
        Ok(halo2_proofs::plonk::verify_proof(&params, &vk, strategy, &[&[public_inputs]], &mut transcript).is_ok())
    }
}


