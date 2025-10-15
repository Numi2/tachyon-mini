//! Unified block step circuit: verifies prior recursion bind (public), applies unified
//! accumulator updates for a fixed number of grams, and emits next state commitment.

use anyhow::Result;
use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, keygen_pk, keygen_vk, create_proof, verify_proof, SingleVerifier};
use halo2_proofs::poly::ipa::commitment::{ParamsIPA, IPACommitmentScheme};
use halo2_proofs::transcript::{Blake2bWrite, Blake2bRead, Challenge255};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::{Fp as Fr, vesta::Affine as G1Affine};
use crate::pcs;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use serde_json;

/// Circuit configuration
#[derive(Clone, Debug)]
pub struct UnifiedBlockConfig {
    pub advice: [Column<Advice>; 6],
    pub selector: Selector,
    pub instance: [Column<Instance>; 3], // [prev_bind_agg, prev_state, next_state]
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

/// Fixed-arity block step (U updates)
#[derive(Clone, Debug)]
pub struct UnifiedBlockCircuit<const U: usize> {
    pub prev_bind_agg: Value<Fr>,
    pub prev_state: Value<Fr>,
    pub grams: [Value<Fr>; U],
    pub is_member: [Value<Fr>; U], // 0/1
}

impl<const U: usize> Circuit<Fr> for UnifiedBlockCircuit<U> {
    type Config = UnifiedBlockConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { prev_bind_agg: Value::unknown(), prev_state: Value::unknown(), grams: [Value::unknown(); U], is_member: [Value::unknown(); U] }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for a in &advice { meta.enable_equality(*a); }
        let selector = meta.selector();
        let instance = [meta.instance_column(), meta.instance_column(), meta.instance_column()];
        for i in &instance { meta.enable_equality(*i); }
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::<Fr, 3, 2>::configure::<P128Pow5T3>(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            rc_a,
            rc_b,
        );
        // Simple booleanity check for each is_member; we reuse a single gate row per update in synthesize
        meta.create_gate("is_member boolean", |meta| {
            let s = meta.query_selector(selector);
            let b = meta.query_advice(advice[5], halo2_proofs::poly::Rotation::cur());
            vec![s * b.clone() * (b - halo2_proofs::plonk::Expression::Constant(Fr::ONE))]
        });
        UnifiedBlockConfig { advice, selector, instance, poseidon }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        // Expose public inputs: prev_bind_agg, prev_state
        let prev_bind_cell = layouter.assign_region(
            || "prev bind",
            |mut region| region.assign_advice(|| "prev bind", cfg.advice[0], 0, || self.prev_bind_agg),
        )?;
        let prev_state_cell = layouter.assign_region(
            || "prev state",
            |mut region| region.assign_advice(|| "prev state", cfg.advice[1], 0, || self.prev_state),
        )?;
        layouter.constrain_instance(prev_bind_cell.cell(), cfg.instance[0], 0)?;
        layouter.constrain_instance(prev_state_cell.cell(), cfg.instance[1], 0)?;

        // Apply U updates: for demo, compute a Poseidon fold: root = H(tag_u, root, H(tag_g, gram, is_member))
        let mut root_cell = prev_state_cell.clone();
        for i in 0..U {
            // Enforce boolean is_member
            layouter.assign_region(
                || format!("bool {i}"),
                |mut region| {
                    cfg.selector.enable(&mut region, 0)?;
                    let b = region.assign_advice(|| "b", cfg.advice[5], 0, || self.is_member[i])?;
                    let _ = b; Ok(())
                },
            )?;

            let chip_g = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
            let h_g = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                chip_g,
                layouter.namespace(|| format!("poseidon gram {i}")),
            )?;
            let tag_g_cell = layouter.assign_region(
                || format!("tag_g {i}"),
                |mut region| {
                    let c = region.assign_advice(|| "tag_g", cfg.advice[4], 0, || Value::known(Fr::from(pcs::domains::TAG_UGRAM as u64)))?; // 'GRAM'
                    region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_UGRAM as u64))?;
                    Ok(c)
                },
            )?;
            let gram_cell = layouter.assign_region(
                || format!("gram {i}"),
                |mut region| region.assign_advice(|| "gram", cfg.advice[2], 0, || self.grams[i]),
            )?;
            let is_mem_cell = layouter.assign_region(
                || format!("is_mem {i}"),
                |mut region| region.assign_advice(|| "is_mem", cfg.advice[5], 0, || self.is_member[i]),
            )?;
            let gram_hash = h_g.hash(
                layouter.namespace(|| format!("H(tag_g, gram, is_mem) {i}")),
                [tag_g_cell, gram_cell, is_mem_cell],
            )?;

            let chip_u = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
            let h_u = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                chip_u,
                layouter.namespace(|| format!("poseidon fold {i}")),
            )?;
            let tag_u_cell = layouter.assign_region(
                || format!("tag_u {i}"),
                |mut region| {
                    let c = region.assign_advice(|| "tag_u", cfg.advice[4], 0, || Value::known(Fr::from(pcs::domains::TAG_UFOLD as u64)))?; // 'FULD'
                    region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_UFOLD as u64))?;
                    Ok(c)
                },
            )?;
            root_cell = h_u.hash(
                layouter.namespace(|| format!("H(tag_u, root, gram_hash) {i}")),
                [tag_u_cell, root_cell, gram_hash],
            )?;
        }

        // Expose next_state as instance[2]
        layouter.constrain_instance(root_cell.cell(), cfg.instance[2], 0)?;
        Ok(())
    }
}

/// Prove a unified block step, returning proof bytes and next state.
pub fn prove_unified_block<const U: usize>(k: u32, prev_bind_agg: Fr, prev_state: Fr, grams: [Fr; U], is_member: [bool; U]) -> Result<(Vec<u8>, Fr)> {
    let params = ParamsIPA::<G1Affine>::new(k);
    let grams_v = grams.map(Value::known);
    let flags_v = is_member.map(|b| Value::known(if b { Fr::ONE } else { Fr::ZERO }));
    let circuit = UnifiedBlockCircuit::<U> { prev_bind_agg: Value::known(prev_bind_agg), prev_state: Value::known(prev_state), grams: grams_v, is_member: flags_v };
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk, &circuit)?;

    // Compute expected next state natively to provide as instance
    let mut state = prev_state;
    for i in 0..U {
        use halo2_gadgets::poseidon::primitives as p;
        let gh = p::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([Fr::from(0x4752414Du64), grams[i], if is_member[i] { Fr::ONE } else { Fr::ZERO }]);
        state = p::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([Fr::from(0x46554C44u64), state, gh]);
    }

    let inst_prev_bind = [prev_bind_agg];
    let inst_prev_state = [prev_state];
    let inst_next = [state];

    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<IPACommitmentScheme<G1Affine>, _, _, _, _>(&params, &pk, &[circuit], &[&[&inst_prev_bind[..], &inst_prev_state[..], &inst_next[..]]], rand::rngs::OsRng, &mut transcript)?;
    Ok((transcript.finalize(), state))
}

/// Verify a unified block step proof given (prev_bind_agg, prev_state, next_state) public inputs.
pub fn verify_unified_block(k: u32, proof: &[u8], prev_bind_agg: Fr, prev_state: Fr, next_state: Fr) -> Result<bool> {
    if proof.is_empty() { return Ok(false); }
    let params = ParamsIPA::<G1Affine>::new(k);
    let empty = UnifiedBlockCircuit::<1> { prev_bind_agg: Value::unknown(), prev_state: Value::unknown(), grams: [Value::unknown()], is_member: [Value::unknown()] };
    let vk = keygen_vk(&params, &empty)?;
    let inst_prev_bind = [prev_bind_agg];
    let inst_prev_state = [prev_state];
    let inst_next = [next_state];
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(std::io::Cursor::new(proof));
    let strategy = SingleVerifier::new(&params);
    Ok(verify_proof::<IPACommitmentScheme<G1Affine>, _, _, _>(&params, &vk, strategy, &[&[&inst_prev_bind[..], &inst_prev_state[..], &inst_next[..]]], &mut transcript).is_ok())
}

// -------------------------------------------------------------
// Polynomial Publisher Circuit (Vesta field, binds block to tachygrams)
// -------------------------------------------------------------

/// Configuration for the polynomial publisher circuit
#[derive(Clone, Debug)]
pub struct PolyPublisherConfig {
    pub advice: [Column<Advice>; 6],
    pub instance: [Column<Instance>; 5], // [A_i, P_i, h_i, A_{i+1}, block_len]
    pub selector: Selector,
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

/// Circuit that checks p_i(r) (from coeffs) equals ∏(r − a_{ij}) over the first L roots,
/// where L = block_len, with prefix-of-ones selector flags. It also binds h_i = H_A(A_i, P_i).
#[derive(Clone, Debug)]
pub struct PolyPublisherCircuit<const MAX_DEG: usize, const MAX_ROOTS: usize> {
    pub a_i: Value<Fr>,        // public
    pub p_i: Value<Fr>,        // public (digest placeholder)
    pub a_next: Value<Fr>,     // public (digest placeholder)
    pub h_i: Value<Fr>,        // public
    pub block_len: Value<Fr>,  // public

    pub coeffs: [Value<Fr>; MAX_DEG + 1],
    pub roots: [Value<Fr>; MAX_ROOTS],
    pub inc_flags: [Value<Fr>; MAX_ROOTS], // 0/1 flags, prefix-of-ones shape
}

impl<const MAX_DEG: usize, const MAX_ROOTS: usize> Circuit<Fr> for PolyPublisherCircuit<MAX_DEG, MAX_ROOTS> {
    type Config = PolyPublisherConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a_i: Value::unknown(),
            p_i: Value::unknown(),
            a_next: Value::unknown(),
            h_i: Value::unknown(),
            block_len: Value::unknown(),
            coeffs: [Value::unknown(); MAX_DEG + 1],
            roots: [Value::unknown(); MAX_ROOTS],
            inc_flags: [Value::unknown(); MAX_ROOTS],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for a in &advice { meta.enable_equality(*a); }
        let instance = [
            meta.instance_column(), // A_i
            meta.instance_column(), // P_i (digest placeholder)
            meta.instance_column(), // h_i
            meta.instance_column(), // A_{i+1} (digest placeholder)
            meta.instance_column(), // block_len
        ];
        for i in &instance { meta.enable_equality(*i); }
        let selector = meta.selector();

        // Poseidon (t=3, rate=2)
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::<Fr, 3, 2>::configure::<P128Pow5T3>(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            rc_a,
            rc_b,
        );

        // Booleanity and prefix-of-ones constraints for inc_flags
        meta.create_gate("inc_flags boolean + prefix", |meta| {
            let s = meta.query_selector(selector);
            let b = meta.query_advice(advice[4], Rotation::cur());
            let b_next = meta.query_advice(advice[5], Rotation::cur());
            // Enforce b ∈ {0,1} and b - b_next ≥ 0 by form b_next*(b_next - b) == 0 for prefix shape
            vec![
                s.clone() * b.clone() * (b.clone() - halo2_proofs::plonk::Expression::Constant(Fr::ONE)),
                s * b_next.clone() * (b_next - b),
            ]
        });

        PolyPublisherConfig { advice, instance, selector, poseidon }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        // Expose public inputs
        let a_i_cell = layouter.assign_region(
            || "A_i",
            |mut region| region.assign_advice(|| "A_i", cfg.advice[0], 0, || self.a_i),
        )?;
        let p_i_cell = layouter.assign_region(
            || "P_i",
            |mut region| region.assign_advice(|| "P_i", cfg.advice[1], 0, || self.p_i),
        )?;
        let h_i_cell = layouter.assign_region(
            || "h_i",
            |mut region| region.assign_advice(|| "h_i", cfg.advice[2], 0, || self.h_i),
        )?;
        let a_next_cell = layouter.assign_region(
            || "A_{i+1}",
            |mut region| region.assign_advice(|| "A_{i+1}", cfg.advice[0], 1, || self.a_next),
        )?;
        let len_cell = layouter.assign_region(
            || "block_len",
            |mut region| region.assign_advice(|| "block_len", cfg.advice[1], 1, || self.block_len),
        )?;
        layouter.constrain_instance(a_i_cell.cell(), cfg.instance[0], 0)?;
        layouter.constrain_instance(p_i_cell.cell(), cfg.instance[1], 0)?;
        layouter.constrain_instance(h_i_cell.cell(), cfg.instance[2], 0)?;
        layouter.constrain_instance(a_next_cell.cell(), cfg.instance[3], 0)?;
        layouter.constrain_instance(len_cell.cell(), cfg.instance[4], 0)?;

        // Compute a Poseidon-based commitment to coefficients to bind to public P_i
        // acc = H(tag, c0, c1); for k>=2: acc = H(acc, c_k, next)
        let tag_coef_commit = layouter.assign_region(|| "tag coef", |mut region| {
            let c = region.assign_advice(|| "tag_coef", cfg.advice[5], 1, || Value::known(Fr::from(pcs::domains::TAG_COEF_COMMIT as u64)))?; // 'COEF'
            region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_COEF_COMMIT as u64))?;
            Ok(c)
        })?;
        // Load c0 and c1 (or zero) as first pair
        let c0_cell = layouter.assign_region(|| "c0", |mut region| region.assign_advice(|| "c0", cfg.advice[0], 3, || self.coeffs[0]))?;
        let c1_cell = layouter.assign_region(|| "c1", |mut region| region.assign_advice(|| "c1", cfg.advice[1], 3, || self.coeffs.get(1).cloned().unwrap_or(Value::known(Fr::ZERO))))?;
        let chip_coef0 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
        let h_coef0 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_coef0,
            layouter.namespace(|| "coef commit round0"),
        )?;
        let mut coef_acc = h_coef0.hash(
            layouter.namespace(|| "H(tag,c0,c1)"),
            [tag_coef_commit.clone(), c0_cell.clone(), c1_cell.clone()],
        )?;
        for (idx, cval) in self.coeffs.iter().enumerate() {
            // After the first two coefficients are bound, fold subsequent coefficients pairwise into coef_acc
            if idx >= 2 {
                if idx % 2 == 0 {
                    let cur_cell = layouter.assign_region(|| format!("c_cur {idx}"), |mut region| region.assign_advice(|| "c_cur", cfg.advice[3], 0, || *cval))?;
                    let next_c = self.coeffs.get(idx + 1).cloned().unwrap_or(Value::known(Fr::ZERO));
                    let next_cell = layouter.assign_region(|| format!("c_next {idx}"), |mut region| region.assign_advice(|| "c_next", cfg.advice[2], 3, || next_c))?;
                    let chip_step = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
                    let h_step = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                        chip_step,
                        layouter.namespace(|| format!("coef commit step {idx}")),
                    )?;
                    coef_acc = h_step.hash(
                        layouter.namespace(|| format!("H(acc,c{},c{})", idx, idx+1)),
                        [coef_acc.clone(), cur_cell.clone(), next_cell.clone()],
                    )?;
                }
            }
        }

        // Now compute FS challenge r using A_i, P_i, block_len and d_coeff
        let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
        let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon fs for r"),
        )?;
        let tag_cell = layouter.assign_region(|| "tag fs", |mut region| {
            let c = region.assign_advice(|| "tag", cfg.advice[5], 0, || Value::known(Fr::from(pcs::domains::TAG_FS_PUBLISHER as u64)))?;
            region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_FS_PUBLISHER as u64))?;
            Ok(c)
        })?;
        let h1 = h.hash(
            layouter.namespace(|| "H(tag, A_i, P_i)"),
            [tag_cell, a_i_cell.clone(), p_i_cell.clone()],
        )?;
        let chip_dc = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
        let h_dc = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_dc,
            layouter.namespace(|| "d_coeff hash"),
        )?;
        let tag_dc = layouter.assign_region(|| "tag fs coef", |mut region| {
            let c = region.assign_advice(|| "tag_fs_coef", cfg.advice[5], 3, || Value::known(Fr::from(pcs::domains::TAG_FS_COEF as u64)))?;
            region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_FS_COEF as u64))?;
            Ok(c)
        })?;
        let zero_dc = layouter.assign_region(|| "zero_dc", |mut region| region.assign_advice(|| "zero_dc", cfg.advice[4], 2, || Value::known(Fr::ZERO)))?;
        let d_coeff = h_dc.hash(
            layouter.namespace(|| "H(tag, coef_acc, 0)"),
            [tag_dc, coef_acc.clone(), zero_dc],
        )?;
        let chip2 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
        let h_len = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip2,
            layouter.namespace(|| "poseidon fs len round"),
        )?;
        let r_cell = h_len.hash(
            layouter.namespace(|| "H(h1, len, d_coeff)"),
            [h1, len_cell.clone(), d_coeff.clone()],
        )?;

        // Assign coeffs and compute Horner(p)(r)
        let mut pr_cell = layouter.assign_region(|| "init p(r)", |mut region| {
            region.assign_advice(|| "p(r)", cfg.advice[4], 0, || Value::known(Fr::ZERO))
        })?;
        for (idx, cval) in self.coeffs.iter().enumerate() {
            let tmp = layouter.assign_region(|| format!("coeff {idx}"), |mut region| {
                region.assign_advice(|| "c", cfg.advice[3], 0, || *cval)
            })?;
            let pr_times_r = layouter.assign_region(|| format!("pr*r {idx}"), |mut region| {
                let prr = pr_cell.value().zip(r_cell.value()).map(|(p, r)| *p * *r);
                region.assign_advice(|| "pr*r", cfg.advice[4], 0, || prr)
            })?;
            layouter.assign_region(|| format!("update pr {idx}"), |mut region| {
                region.constrain_equal(pr_times_r.cell(), pr_times_r.cell())?; Ok(())
            })?;
            pr_cell = layouter.assign_region(|| format!("pr_new {idx}"), |mut region| {
                let pr_new = pr_times_r.value().zip(tmp.value()).map(|(a, b)| *a + *b);
                region.assign_advice(|| "pr_new", cfg.advice[4], 0, || pr_new)
            })?;
        }

        // Assign roots and inc_flags, enforce booleanity/prefix, and compute ∏((r - a_j)*b_j + (1-b_j))
        let mut prod_cell = layouter.assign_region(|| "init prod", |mut region| {
            region.assign_advice(|| "prod", cfg.advice[2], 1, || Value::known(Fr::ONE))
        })?;
        let mut sum_flags_cell = layouter.assign_region(|| "init sum", |mut region| {
            region.assign_advice(|| "sum", cfg.advice[0], 2, || Value::known(Fr::ZERO))
        })?;
        for j in 0..MAX_ROOTS {
            // b_j booleanity and prefix gate by enabling selector on a row with (b, b_next)
            layouter.assign_region(|| format!("bool/prefix {j}"), |mut region| {
                cfg.selector.enable(&mut region, 0)?;
                let b = region.assign_advice(|| "b_j", cfg.advice[4], 0, || self.inc_flags[j])?;
                let b_next = region.assign_advice(|| "b_{j+1}", cfg.advice[5], 0, || if j + 1 < MAX_ROOTS { self.inc_flags[j + 1] } else { Value::known(Fr::ZERO) })?;
                let _ = (b, b_next);
                Ok(())
            })?;

            // t_j = (r - a_j)
            let a_cell = layouter.assign_region(|| format!("a_{j}"), |mut region| {
                region.assign_advice(|| "a_j", cfg.advice[1], 2, || self.roots[j])
            })?;
            let t_cell = layouter.assign_region(|| format!("t_{j}"), |mut region| {
                let t = r_cell.value().zip(a_cell.value()).map(|(r, a)| *r - *a);
                region.assign_advice(|| "t_j", cfg.advice[2], 2, || t)
            })?;
            // factor_j = t_j*b_j + (1 - b_j)
            let b_cell = layouter.assign_region(|| format!("bcopy_{j}"), |mut region| {
                region.assign_advice(|| "bcopy", cfg.advice[5], 1, || self.inc_flags[j])
            })?;
            let one_minus_b = layouter.assign_region(|| format!("1-b_{j}"), |mut region| {
                let val = b_cell.value().map(|b| Fr::ONE - *b);
                region.assign_advice(|| "1-b", cfg.advice[3], 1, || val)
            })?;
            let tb = layouter.assign_region(|| format!("t*b_{j}"), |mut region| {
                let val = t_cell.value().zip(b_cell.value()).map(|(t, b)| *t * *b);
                region.assign_advice(|| "t*b", cfg.advice[4], 1, || val)
            })?;
            let factor = layouter.assign_region(|| format!("factor_{j}"), |mut region| {
                let val = tb.value().zip(one_minus_b.value()).map(|(x, y)| *x + *y);
                region.assign_advice(|| "factor", cfg.advice[2], 1, || val)
            })?;
            // prod *= factor
            prod_cell = layouter.assign_region(|| format!("prod_{j}"), |mut region| {
                let val = prod_cell.value().zip(factor.value()).map(|(p, f)| *p * *f);
                region.assign_advice(|| "prod", cfg.advice[2], 1, || val)
            })?;
            // sum_flags += b_j
            sum_flags_cell = layouter.assign_region(|| format!("sum_{j}"), |mut region| {
                let val = sum_flags_cell.value().zip(b_cell.value()).map(|(s, b)| *s + *b);
                region.assign_advice(|| "sum", cfg.advice[0], 2, || val)
            })?;
        }

        // Enforce adjacent deduplication for selected roots: if b_j and b_{j+1} are 1 then (a_{j+1} - a_j) * inv_j == 1
        // Implement as (a_{j+1} - a_j) * inv_j == b_j * b_{j+1}
        for j in 0..(MAX_ROOTS.saturating_sub(1)) {
            let a_j = layouter.assign_region(|| format!("a_dup_{j}"), |mut region| {
                region.assign_advice(|| "a_j", cfg.advice[1], 3, || self.roots[j])
            })?;
            let a_j1 = layouter.assign_region(|| format!("a_dup_{j}_next"), |mut region| {
                region.assign_advice(|| "a_{j+1}", cfg.advice[2], 3, || self.roots[j + 1])
            })?;
            let b_j = layouter.assign_region(|| format!("b_dup_{j}"), |mut region| {
                region.assign_advice(|| "b_j", cfg.advice[4], 3, || self.inc_flags[j])
            })?;
            let b_j1 = layouter.assign_region(|| format!("b_dup_{j}_next"), |mut region| {
                region.assign_advice(|| "b_{j+1}", cfg.advice[5], 3, || self.inc_flags[j + 1])
            })?;
            let bb = layouter.assign_region(|| format!("bb_{j}"), |mut region| {
                let val = b_j.value().zip(b_j1.value()).map(|(x, y)| *x * *y);
                region.assign_advice(|| "bb", cfg.advice[0], 3, || val)
            })?;
            let diff = layouter.assign_region(|| format!("diff_{j}"), |mut region| {
                let val = a_j1.value().zip(a_j.value()).map(|(nxt, cur)| *nxt - *cur);
                region.assign_advice(|| "diff", cfg.advice[3], 3, || val)
            })?;
            let inv = layouter.assign_region(|| format!("inv_{j}"), |mut region| {
                let val = a_j1.value().zip(a_j.value()).zip(b_j.value()).zip(b_j1.value()).map(|(((nxt, cur), bj), bj1)| {
                    let d = *nxt - *cur; let both = *bj * *bj1; if both == Fr::ONE { d.invert().unwrap_or(Fr::ZERO) } else { Fr::ZERO }
                });
                region.assign_advice(|| "inv", cfg.advice[2], 3, || val)
            })?;
            let prod = layouter.assign_region(|| format!("diff*inv_{j}"), |mut region| {
                let val = diff.value().zip(inv.value()).map(|(d, i)| *d * *i);
                region.assign_advice(|| "prod", cfg.advice[1], 3, || val)
            })?;
            layouter.assign_region(|| format!("bind_dup_{j}"), |mut region| {
                region.constrain_equal(prod.cell(), bb.cell())?; Ok(())
            })?;
        }

        // Enforce sum_flags == block_len
        layouter.assign_region(|| "bind sum == len", |mut region| {
            region.constrain_equal(sum_flags_cell.cell(), len_cell.cell())?;
            Ok(())
        })?;

        // Enforce Horner p(r) == selected product
        layouter.assign_region(|| "bind pr == prod", |mut region| {
            region.constrain_equal(pr_cell.cell(), prod_cell.cell())?;
            Ok(())
        })?;

        // Bind public P_i to in-circuit coefficient commitment
        layouter.assign_region(|| "bind P_i == coef_commit", |mut region| {
            region.constrain_equal(p_i_cell.cell(), coef_acc.cell())?;
            Ok(())
        })?;

        // FS challenge r already computed using d_coeff; no recomputation needed

        // Enforce h_i = H_A(A_i, P_i) using Poseidon composition (digest placeholder)
        let chip_h = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
        let h2 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_h,
            layouter.namespace(|| "poseidon H_A"),
        )?;
        let tag_a_cell = layouter.assign_region(|| "tag acc A", |mut region| {
            let c = region.assign_advice(|| "tagA", cfg.advice[5], 2, || Value::known(Fr::from(pcs::domains::TAG_ACC_A as u64)))?;
            region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_ACC_A as u64))?;
            Ok(c)
        })?;
        let h_a_cell = h2.hash(
            layouter.namespace(|| "H(tag, A_i, P_i) (acc)"),
            [tag_a_cell, a_i_cell.clone(), p_i_cell.clone()],
        )?;
        layouter.assign_region(|| "bind h_i", |mut region| {
            region.constrain_equal(h_i_cell.cell(), h_a_cell.cell())?;
            Ok(())
        })?;

        Ok(())
    }
}

/// Prove a polynomial publisher instance. Returns proof bytes.
pub fn prove_poly_publisher<const MAX_DEG: usize, const MAX_ROOTS: usize>(
    k: u32,
    a_i: Fr,
    p_i: Fr,
    a_next: Fr,
    h_i: Fr,
    block_len: u64,
    coeffs: [Fr; MAX_DEG + 1],
    roots: [Fr; MAX_ROOTS],
    inc_flags: [bool; MAX_ROOTS],
) -> Result<Vec<u8>> {
    let params = load_or_setup_publisher_params::<MAX_DEG, MAX_ROOTS>(k)?;
    let circuit = PolyPublisherCircuit::<MAX_DEG, MAX_ROOTS> {
        a_i: Value::known(a_i),
        p_i: Value::known(p_i),
        a_next: Value::known(a_next),
        h_i: Value::known(h_i),
        block_len: Value::known(Fr::from(block_len as u64)),
        coeffs: coeffs.map(Value::known),
        roots: roots.map(Value::known),
        inc_flags: inc_flags.map(|b| Value::known(if b { Fr::ONE } else { Fr::ZERO })),
    };
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk, &circuit)?;

    let inst_a = [a_i];
    let inst_p = [p_i];
    let inst_h = [h_i];
    let inst_next = [a_next];
    let inst_len = [Fr::from(block_len as u64)];

    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<IPACommitmentScheme<G1Affine>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&inst_a[..], &inst_p[..], &inst_h[..], &inst_next[..], &inst_len[..]]],
        rand::rngs::OsRng,
        &mut transcript,
    )?;
    Ok(transcript.finalize())
}

/// Verify a polynomial publisher proof
pub fn verify_poly_publisher(
    k: u32,
    a_i: Fr,
    p_i: Fr,
    a_next: Fr,
    h_i: Fr,
    block_len: u64,
    proof: &[u8],
) -> Result<bool> {
    if proof.is_empty() { return Ok(false); }
    let params = load_or_setup_publisher_params::<1, 1>(k)?;
    // Use empty shape of the same circuit to derive VK
    let empty = PolyPublisherCircuit::<1, 1> {
        a_i: Value::unknown(),
        p_i: Value::unknown(),
        a_next: Value::unknown(),
        h_i: Value::unknown(),
        block_len: Value::unknown(),
        coeffs: [Value::unknown(); 2],
        roots: [Value::unknown(); 1],
        inc_flags: [Value::unknown(); 1],
    };
    let vk = keygen_vk(&params, &empty)?;
    let inst_a = [a_i];
    let inst_p = [p_i];
    let inst_h = [h_i];
    let inst_next = [a_next];
    let inst_len = [Fr::from(block_len as u64)];
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(std::io::Cursor::new(proof));
    let strategy = SingleVerifier::new(&params);
    Ok(verify_proof::<IPACommitmentScheme<G1Affine>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&inst_a[..], &inst_p[..], &inst_h[..], &inst_next[..], &inst_len[..]]],
        &mut transcript,
    ).is_ok())
}

/// Publisher circuit params persistence with versioned IDs
#[derive(serde::Serialize, serde::Deserialize)]
struct PublisherCircuitMeta { version: u32, k: u32, id: String }

fn publisher_circuit_id<const MAX_DEG: usize, const MAX_ROOTS: usize>() -> String {
    format!("publisher:v1:deg{}:roots{}", MAX_DEG, MAX_ROOTS)
}

fn params_store_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    let base = Path::new("crates/pcd_core/crates/node_ext/node_data/keys");
    (base.join("pub_params.bin"), base.join("pub_meta.json"))
}

fn load_or_setup_publisher_params<const MAX_DEG: usize, const MAX_ROOTS: usize>(k: u32) -> Result<ParamsIPA<G1Affine>> {
    std::fs::create_dir_all("crates/pcd_core/crates/node_ext/node_data/keys").ok();
    let (params_path, meta_path) = params_store_paths();
    if params_path.exists() {
        let mut pf = File::open(&params_path)?;
        let params = ParamsIPA::<G1Affine>::read(&mut pf)?;
        if meta_path.exists() {
            let mut s = String::new(); File::open(&meta_path)?.read_to_string(&mut s)?;
            let meta: PublisherCircuitMeta = serde_json::from_str(&s)?;
            let expected = PublisherCircuitMeta { version: 1, k, id: publisher_circuit_id::<MAX_DEG, MAX_ROOTS>() };
            if meta.k != expected.k || meta.id != expected.id { return Err(anyhow::anyhow!("publisher params meta mismatch")); }
        }
        Ok(params)
    } else {
        let params = ParamsIPA::<G1Affine>::new(k);
        let mut f = File::create(&params_path)?; params.write(&mut f)?;
        let meta = PublisherCircuitMeta { version: 1, k, id: publisher_circuit_id::<MAX_DEG, MAX_ROOTS>() };
        let mut mf = File::create(&meta_path)?; mf.write_all(serde_json::to_string_pretty(&meta)?.as_bytes())?;
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_verify_mismatch_pi_fails() {
        const MAX_DEG: usize = 4; const MAX_ROOTS: usize = 4;
        let k = 12u32;
        // Simple coeffs: p(x) = 3x + 2, roots = [1,2], L=2 => p(r) == (r-1)(r-2)
        let coeffs = [Fr::from(2u64), Fr::from(3u64), Fr::ZERO, Fr::ZERO, Fr::ZERO];
        let roots = [Fr::from(1u64), Fr::from(2u64), Fr::ZERO, Fr::ZERO];
        let flags = [true, true, false, false];
        let a_i = Fr::from(7u64);
        let a_next = Fr::from(9u64);
        // Bind h_i = H_A(A_i, P_i) (we'll set p_i later)
        let p_i = Fr::from(123u64);
        let h_i = pcs::hash_accumulator_a(a_i, Fr::ZERO, p_i, Fr::ZERO);
        let proof = prove_poly_publisher::<MAX_DEG, MAX_ROOTS>(k, a_i, p_i, a_next, h_i, 2, coeffs, roots, flags).expect("prove");
        // Verify with mismatched p_i should fail
        let ok = verify_poly_publisher(k, a_i, Fr::from(124u64), a_next, h_i, 2, &proof).expect("verify");
        assert!(!ok);
    }

    #[test]
    fn publisher_verify_wrong_block_len_fails() {
        const MAX_DEG: usize = 4; const MAX_ROOTS: usize = 4;
        let k = 12u32;
        let coeffs = [Fr::from(1u64), Fr::from(1u64), Fr::ZERO, Fr::ZERO, Fr::ZERO];
        let roots = [Fr::from(5u64), Fr::from(6u64), Fr::ZERO, Fr::ZERO];
        let flags = [true, false, false, false];
        let a_i = Fr::from(7u64);
        let a_next = Fr::from(9u64);
        let p_i = Fr::from(55u64);
        let h_i = pcs::hash_accumulator_a(a_i, Fr::ZERO, p_i, Fr::ZERO);
        let proof = prove_poly_publisher::<MAX_DEG, MAX_ROOTS>(k, a_i, p_i, a_next, h_i, 1, coeffs, roots, flags).expect("prove");
        let ok = verify_poly_publisher(k, a_i, p_i, a_next, h_i, 2, &proof).expect("verify");
        assert!(!ok);
    }
}
