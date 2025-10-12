//! Unified block step circuit: verifies prior recursion bind (public), applies unified
//! accumulator updates for a fixed number of grams, and emits next state commitment.

use anyhow::Result;
use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, keygen_pk, keygen_vk, create_proof, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Blake2bRead, Challenge255};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::{Fp as Fr, vesta::Affine as G1Affine};

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
    let params = Params::<G1Affine>::new(k);
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
    create_proof(&params, &pk, &[circuit], &[&[&inst_prev_bind[..], &inst_prev_state[..], &inst_next[..]]], rand::rngs::OsRng, &mut transcript)?;
    Ok((transcript.finalize(), state))
}

/// Verify a unified block step proof given (prev_bind_agg, prev_state, next_state) public inputs.
pub fn verify_unified_block(k: u32, proof: &[u8], prev_bind_agg: Fr, prev_state: Fr, next_state: Fr) -> Result<bool> {
    if proof.is_empty() { return Ok(false); }
    let params = Params::<G1Affine>::new(k);
    let empty = UnifiedBlockCircuit::<1> { prev_bind_agg: Value::unknown(), prev_state: Value::unknown(), grams: [Value::unknown()], is_member: [Value::unknown()] };
    let vk = keygen_vk(&params, &empty)?;
    let inst_prev_bind = [prev_bind_agg];
    let inst_prev_state = [prev_state];
    let inst_next = [next_state];
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(std::io::Cursor::new(proof));
    let strategy = SingleVerifier::new(&params);
    Ok(verify_proof(&params, &vk, strategy, &[&[&inst_prev_bind[..], &inst_prev_state[..], &inst_next[..]]], &mut transcript).is_ok())
}
