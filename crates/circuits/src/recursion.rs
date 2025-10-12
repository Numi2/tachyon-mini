//! Recursion verifier circuit (Poseidon-binder): aggregates inner proof commitments.
//!
//! This circuit computes `agg = H(TAG_REC, prev, cur)` with Poseidon2 (t=3, rate=2)
//! and exposes `agg` as a public instance. It is intended to recursively bind
//! previously-verified proofs into a single succinct accumulator, while keeping
//! the verifier cost O(1). Inner proof validity should be established prior to
//! invoking this circuit (e.g., on host or via a higher-order verification).

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;

/// Domain separation tag for recursion binder
const TAG_REC: u64 = 0x52554330; // 'RUC0'

#[derive(Clone, Debug)]
pub struct RecPoseidonConfig {
    pub advice: [Column<Advice>; 4],
    pub selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

#[derive(Clone, Debug)]
pub struct RecPoseidonCircuit {
    pub prev: Value<Fr>,
    pub cur: Value<Fr>,
    pub agg: Value<Fr>,
}

impl Circuit<Fr> for RecPoseidonCircuit {
    type Config = RecPoseidonConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { prev: Value::unknown(), cur: Value::unknown(), agg: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for a in &advice { meta.enable_equality(*a); }
        let selector = meta.selector();
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::<Fr, 3, 2>::configure::<P128Pow5T3>(meta, [advice[0], advice[1], advice[2]], advice[3], rc_a, rc_b);
        RecPoseidonConfig { advice, selector, instance, poseidon }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        // Assign prev/cur/agg and compute digest = H(TAG_REC, prev, cur)
        let prev_cell = layouter.assign_region(
            || "prev",
            |mut region| region.assign_advice(|| "prev", cfg.advice[0], 0, || self.prev),
        )?;
        let cur_cell = layouter.assign_region(
            || "cur",
            |mut region| region.assign_advice(|| "cur", cfg.advice[1], 0, || self.cur),
        )?;
        let agg_cell = layouter.assign_region(
            || "agg",
            |mut region| region.assign_advice(|| "agg", cfg.advice[2], 0, || self.agg),
        )?;

        let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
        let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip,
            layouter.namespace(|| "rec poseidon"),
        )?;
        let tag_cell = layouter.assign_region(
            || "tag",
            |mut region| {
                let c = region.assign_advice(|| "tag", cfg.advice[3], 0, || Value::known(Fr::from(TAG_REC)))?;
                region.constrain_constant(c.cell(), Fr::from(TAG_REC))?;
                Ok(c)
            },
        )?;
        let digest = h.hash(layouter.namespace(|| "H(tag, prev, cur)"), [tag_cell, prev_cell.clone(), cur_cell.clone()])?;

        // Enforce agg == digest
        layouter.assign_region(
            || "bind agg",
            |mut region| {
                cfg.selector.enable(&mut region, 0)?;
                let d = region.assign_advice(|| "digest", cfg.advice[0], 0, || digest.value().copied())?;
                region.constrain_equal(d.cell(), digest.cell())?;
                region.constrain_equal(d.cell(), agg_cell.cell())?;
                Ok(())
            },
        )?;

        // Expose agg as public input index 0
        layouter.constrain_instance(agg_cell.cell(), cfg.instance, 0)?;
        Ok(())
    }
}

/// Stateless helper to compute aggregated commitment outside the circuit
pub fn compute_rec_agg(prev: Fr, cur: Fr) -> Fr {
    use halo2_gadgets::poseidon::primitives as p;
    p::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([Fr::from(TAG_REC), prev, cur])
}


