//! Orchard-oriented gadgets and circuit skeletons.
//!
//! This module provides production-grade building blocks required to express
//! Orchard-like note commitment checks, nullifier derivations, and membership
//! paths over Poseidon2-compatible hashes on Pasta. It intentionally avoids
//! specifying spend authorization details and focuses on accumulator and
//! constraint soundness.

#![allow(dead_code)]

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;

use crate::sparse_merkle::SparseMerkleConfig;

/// Orchard constants and tags for domain separation
pub mod domain {
    use super::*;
    pub const TAG_NOTE_COMMIT: u64 = 101;
    pub const TAG_NULLIFIER: u64 = 102;

    pub fn tag_to_fr(tag: u64) -> Fr { Fr::from(tag) }
}

/// Poseidon2(t=3, rate=2) configuration wrapper
#[derive(Clone, Debug)]
pub struct Poseidon2Config {
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

impl Poseidon2Config {
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: &[Column<Advice>; 6]) -> Self {
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
        Self { poseidon }
    }
}

/// Gadget: note commitment = H(TAG_NOTE_COMMIT, pk, value)
pub fn note_commitment<const DEPTH: usize>(
    mut layouter: impl Layouter<Fr>,
    cfg: &OrchardMembershipConfig<DEPTH>,
    pk: Value<Fr>,
    value: Value<Fr>,
) -> Result<halo2_proofs::circuit::AssignedCell<Fr, Fr>, Error> {
    let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
    let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
        chip,
        layouter.namespace(|| "poseidon note commitment"),
    )?;

    let tag_cell = layouter.assign_region(
        || "tag_note_commit",
        |mut region| {
            let c = region.assign_advice(|| "tag", cfg.advice[0], 0, || Value::known(domain::tag_to_fr(domain::TAG_NOTE_COMMIT)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NOTE_COMMIT))?;
            Ok(c)
        },
    )?;

    // Assign inputs
    let pk_cell = layouter.assign_region(
        || "pk",
        |mut region| region.assign_advice(|| "pk", cfg.advice[1], 0, || pk),
    )?;
    let val_cell = layouter.assign_region(
        || "value",
        |mut region| region.assign_advice(|| "value", cfg.advice[2], 0, || value),
    )?;

    let cm = h.hash(layouter.namespace(|| "H(tag, pk, v)"), [tag_cell, pk_cell, val_cell])?;
    Ok(cm)
}

/// Gadget: nullifier = H(TAG_NULLIFIER, commitment, rho)
pub fn nullifier<const DEPTH: usize>(
    mut layouter: impl Layouter<Fr>,
    cfg: &OrchardMembershipConfig<DEPTH>,
    commitment: halo2_proofs::circuit::AssignedCell<Fr, Fr>,
    rho: Value<Fr>,
) -> Result<halo2_proofs::circuit::AssignedCell<Fr, Fr>, Error> {
    let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
    let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
        chip,
        layouter.namespace(|| "poseidon nullifier"),
    )?;
    let tag_cell = layouter.assign_region(
        || "tag_nullifier",
        |mut region| {
            let c = region.assign_advice(|| "tag", cfg.advice[0], 0, || Value::known(domain::tag_to_fr(domain::TAG_NULLIFIER)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NULLIFIER))?;
            Ok(c)
        },
    )?;
    let rho_cell = layouter.assign_region(
        || "rho",
        |mut region| region.assign_advice(|| "rho", cfg.advice[1], 0, || rho),
    )?;
    let nf = h.hash(layouter.namespace(|| "H(tag, cm, rho)"), [tag_cell, commitment, rho_cell])?;
    Ok(nf)
}

/// Orchard membership circuit skeleton: verifies commitment inclusion and derives nullifier.
#[derive(Clone, Debug)]
pub struct OrchardMembershipConfig<const DEPTH: usize> {
    pub advice: [Column<Advice>; 6],
    pub selector: Selector,
    pub poseidon: Poseidon2Config,
    pub smt: SparseMerkleConfig,
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct OrchardMembershipCircuit<const DEPTH: usize> {
    pub pk: Value<Fr>,
    pub value: Value<Fr>,
    pub rho: Value<Fr>,
    pub siblings: [Value<Fr>; DEPTH],
    pub directions: [Value<Fr>; DEPTH],
}

impl<const DEPTH: usize> Circuit<Fr> for OrchardMembershipCircuit<DEPTH> {
    type Config = OrchardMembershipConfig<DEPTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            pk: Value::unknown(),
            value: Value::unknown(),
            rho: Value::unknown(),
            siblings: [Value::unknown(); DEPTH],
            directions: [Value::unknown(); DEPTH],
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
        let selector = meta.selector();
        let poseidon = Poseidon2Config::configure(meta, &advice);
        let smt = SparseMerkleConfig::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        OrchardMembershipConfig { advice, selector, poseidon, smt, instance }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 1) Compute note commitment = H(TAG_NOTE_COMMIT, pk, value)
        let cm = note_commitment(
            layouter.namespace(|| "note commitment"),
            &cfg,
            self.pk,
            self.value,
        )?;

        // 2) Verify Merkle membership up to root
        let mut cur = cm.clone();
        for i in 0..DEPTH {
            // Assign sibling and direction, and perform linear selection
            let (x, y) = layouter.assign_region(
                || format!("lin sel {i}"),
                |mut region| {
                    cfg.smt.selector.enable(&mut region, 0)?;
                    let leaf_row = region.assign_advice(|| "leaf_row", cfg.smt.advice[0], 0, || cur.value().copied())?;
                    region.constrain_equal(leaf_row.cell(), cur.cell())?;
                    let _sib = region.assign_advice(|| "sib", cfg.smt.advice[1], 0, || self.siblings[i])?;
                    let dir_cell = region.assign_advice(|| "dir", cfg.smt.advice[5], 0, || self.directions[i])?;
                    let x = region.assign_advice(|| "x", cfg.smt.advice[2], 0, || {
                        self.directions[i].zip(cur.value().copied()).zip(self.siblings[i]).map(|((d, l), s)| {
                            let one = Fr::ONE; (one - d) * l + d * s
                        })
                    })?;
                    let y = region.assign_advice(|| "y", cfg.smt.advice[3], 0, || {
                        self.directions[i].zip(cur.value().copied()).zip(self.siblings[i]).map(|((d, l), s)| {
                            d * l + (Fr::ONE - d) * s
                        })
                    })?;
                    let _ = dir_cell;
                    Ok((x, y))
                },
            )?;
            let out = cfg.smt.hash_level(layouter.namespace(|| format!("hash level {i}")), x, y)?;
            cur = out;
        }

        // 3) Derive nullifier = H(TAG_NULLIFIER, commitment, rho)
        let _nullifier = nullifier(layouter.namespace(|| "nullifier"), &cfg, cm, self.rho)?;

        // 4) Expose root as public input 0
        layouter.constrain_instance(cur.cell(), cfg.instance, 0)?;
        Ok(())
    }
}


