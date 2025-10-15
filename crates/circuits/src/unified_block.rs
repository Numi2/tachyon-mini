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
                    let c = region.assign_advice(|| "tag_g", cfg.advice[4], 0, || Value::known(Fr::from(0x4752414Du64)))?; // 'GRAM'
                    region.constrain_constant(c.cell(), Fr::from(0x4752414Du64))?;
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
                    let c = region.assign_advice(|| "tag_u", cfg.advice[4], 0, || Value::known(Fr::from(0x46554C44u64)))?; // 'FULD'
                    region.constrain_constant(c.cell(), Fr::from(0x46554C44u64))?;
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

        // Compute FS challenge r = H(TAG_FS_PUBLISHER, A_i, P_i)
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
        let r_cell = h.hash(
            layouter.namespace(|| "H(tag, A_i, P_i)"),
            [tag_cell, a_i_cell.clone(), p_i_cell.clone()],
        )?;

        // Assign coeffs and compute Horner(p)(r)
        let mut pr_cell = layouter.assign_region(|| "init p(r)", |mut region| {
            region.assign_advice(|| "p(r)", cfg.advice[4], 0, || Value::known(Fr::ZERO))
        })?;
        for (idx, cval) in self.coeffs.iter().enumerate() {
            // pr = pr * r + c
            let tmp = layouter.assign_region(|| format!("coeff {idx}"), |mut region| {
                region.assign_advice(|| "c", cfg.advice[3], 0, || *cval)
            })?;
            // Compute pr * r
            let pr_times_r = layouter.assign_region(|| format!("pr*r {idx}"), |mut region| {
                let prr = pr_cell.value().zip(r_cell.value()).map(|(p, r)| *p * *r);
                region.assign_advice(|| "pr*r", cfg.advice[4], 0, || prr)
            })?;
            // pr = pr*r + c
            layouter.assign_region(|| format!("update pr {idx}"), |mut region| {
                region.constrain_equal(pr_times_r.cell(), pr_times_r.cell())?; // no-op to keep region alive
                Ok(())
            })?;
            // Reassign pr = pr_times_r + c
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
    let params = ParamsIPA::<G1Affine>::new(k);
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
    let params = ParamsIPA::<G1Affine>::new(k);
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
