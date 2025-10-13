//! Tachyactions: minimal spend/output circuit skeleton over Fr with SMT checks and Poseidon digest.
//! Numan Thabit 2025

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;
use ff::Field;

use crate::sparse_merkle::SparseMerkleConfig;

#[derive(Clone, Debug)]
pub struct TachyConfig {
    pub advice: [Column<Advice>; 6],
    pub selector: Selector,
    pub instance: [Column<Instance>; 2], // 0: accumulator root, 1: digest
    pub poseidon: Pow5Config<Fr, 3, 2>,
    pub smt: SparseMerkleConfig,
}

#[derive(Clone, Debug)]
pub struct TachyActionCircuit<const D: usize> {
    pub acc_root_before: Value<Fr>,
    pub acc_root_after: Value<Fr>,
    pub leaf_old: Value<Fr>,
    pub leaf_new: Value<Fr>,
    pub siblings: [Value<Fr>; D],
    pub directions: [Value<Fr>; D],
    pub payment_key: Value<Fr>,
    pub value: Value<Fr>,
    pub nonce: Value<Fr>,
    // Simplified Schnorr-like signature components over the base field
    pub sig_r: Value<Fr>,
    pub sig_s: Value<Fr>,
}

impl<const D: usize> Circuit<Fr> for TachyActionCircuit<D> {
    type Config = TachyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            acc_root_before: Value::unknown(),
            acc_root_after: Value::unknown(),
            leaf_old: Value::unknown(),
            leaf_new: Value::unknown(),
            siblings: [Value::unknown(); D],
            directions: [Value::unknown(); D],
            payment_key: Value::unknown(),
            value: Value::unknown(),
            nonce: Value::unknown(),
            sig_r: Value::unknown(),
            sig_s: Value::unknown(),
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
        let selector = meta.selector();
        let instance = [meta.instance_column(), meta.instance_column()];
        for a in &advice { meta.enable_equality(*a); }
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

        let smt = SparseMerkleConfig::configure(meta);

        // Signature linear relation gate (toy-Schnorr over the field):
        // Enforce s = r + chal * pk in one row when selector is enabled.
        // Here pk is the payment_key field element and chal is a Poseidon challenge
        // derived from (tag_sig, digest, pk).
        meta.create_gate("sig_linear_check", |meta| {
            let s = meta.query_selector(selector);
            let pk = meta.query_advice(advice[0], Rotation::cur());
            let chal = meta.query_advice(advice[1], Rotation::cur());
            let r = meta.query_advice(advice[2], Rotation::cur());
            let sig_s = meta.query_advice(advice[3], Rotation::cur());
            // Constraint: sig_s - (r + chal * pk) == 0
            vec![s * (sig_s - (r + chal * pk))]
        });

        TachyConfig { advice, selector, instance, poseidon, smt }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 1) Assign before/after roots and leaves
        let acc_before_cell = layouter.assign_region(
            || "acc before",
            |mut region| region.assign_advice(|| "acc_before", config.smt.advice[0], 0, || self.acc_root_before),
        )?;
        let acc_after_cell = layouter.assign_region(
            || "acc after",
            |mut region| region.assign_advice(|| "acc_after", config.smt.advice[1], 0, || self.acc_root_after),
        )?;
        let mut cur_old = layouter.assign_region(
            || "leaf_old",
            |mut region| region.assign_advice(|| "leaf_old", config.smt.advice[0], 0, || self.leaf_old),
        )?;
        let leaf_new_cell = layouter.assign_region(
            || "leaf_new",
            |mut region| region.assign_advice(|| "leaf_new", config.smt.advice[0], 0, || self.leaf_new),
        )?;
        let mut cur_new = leaf_new_cell.clone();

        // 2) Walk the path to compute old and new roots
        for i in 0..D {
            // Old path selection: assign dir and sib in the same row as the gate
            let (x_old, y_old, _dir_old) = layouter.assign_region(
                || format!("lin sel old {i}"),
                |mut region| {
                    config.smt.selector.enable(&mut region, 0)?;
                    let _sib = region.assign_advice(|| "sib_old", config.smt.advice[1], 0, || self.siblings[i])?;
                    let dir_cell = region.assign_advice(|| "dir_old", config.smt.advice[5], 0, || self.directions[i])?;
                    let x = region.assign_advice(|| "x_old", config.smt.advice[2], 0, || {
                        self.directions[i].zip(cur_old.value()).zip(self.siblings[i]).map(|((d, l), s)| {
                            let one = Fr::ONE;
                            (one - d) * l + d * s
                        })
                    })?;
                    let y = region.assign_advice(|| "y_old", config.smt.advice[3], 0, || {
                        self.directions[i].zip(cur_old.value()).zip(self.siblings[i]).map(|((d, l), s)| {
                            d * l + (Fr::ONE - d) * s
                        })
                    })?;
                    Ok((x, y, dir_cell))
                },
            )?;
            cur_old = config.smt.hash_level(
                layouter.namespace(|| format!("hash old {i}")),
                x_old,
                y_old,
            )?;

            // New path selection (same siblings/directions): assign again in the gate row
            let (x_new, y_new, _dir_new) = layouter.assign_region(
                || format!("lin sel new {i}"),
                |mut region| {
                    config.smt.selector.enable(&mut region, 0)?;
                    let _sib = region.assign_advice(|| "sib_new", config.smt.advice[1], 0, || self.siblings[i])?;
                    let dir_cell = region.assign_advice(|| "dir_new", config.smt.advice[5], 0, || self.directions[i])?;
                    let x = region.assign_advice(|| "x_new", config.smt.advice[2], 0, || {
                        self.directions[i].zip(cur_new.value()).zip(self.siblings[i]).map(|((d, l), s)| {
                            let one = Fr::ONE;
                            (one - d) * l + d * s
                        })
                    })?;
                    let y = region.assign_advice(|| "y_new", config.smt.advice[3], 0, || {
                        self.directions[i].zip(cur_new.value()).zip(self.siblings[i]).map(|((d, l), s)| {
                            d * l + (Fr::ONE - d) * s
                        })
                    })?;
                    Ok((x, y, dir_cell))
                },
            )?;
            cur_new = config.smt.hash_level(
                layouter.namespace(|| format!("hash new {i}")),
                x_new,
                y_new,
            )?;
        }

        // 3) Enforce old/new root consistency with provided before/after
        layouter.assign_region(
            || "enforce roots",
            |mut region| {
                region.constrain_equal(acc_before_cell.cell(), cur_old.cell())?;
                region.constrain_equal(acc_after_cell.cell(), cur_new.cell())?;
                Ok(())
            },
        )?;

        // 4) Compute digest over (payment_key, value, nonce) via Poseidon with domain separation
        // inner = H(tag_in, pk, val), digest = H(tag_out, inner, nonce)
        let chip_in = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
        let h_in = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_in,
            layouter.namespace(|| "poseidon inner"),
        )?;
        let tag_in = layouter.assign_region(
            || "tag_in",
            |mut region| {
                let c = region.assign_advice(|| "tag_in", config.advice[5], 0, || Value::known(Fr::from(31u64)))?;
                region.constrain_constant(c.cell(), Fr::from(31u64))?;
                Ok(c)
            },
        )?;
        let pk = layouter.assign_region(
            || "payment_key",
            |mut region| region.assign_advice(|| "pk", config.advice[0], 0, || self.payment_key),
        )?;
        let val = layouter.assign_region(
            || "value",
            |mut region| region.assign_advice(|| "value", config.advice[1], 0, || self.value),
        )?;
        let nonce = layouter.assign_region(
            || "nonce",
            |mut region| region.assign_advice(|| "nonce", config.advice[2], 0, || self.nonce),
        )?;
        let inner = h_in.hash(
            layouter.namespace(|| "hash inner"),
            [tag_in, pk.clone(), val],
        )?;
        let chip_out = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
        let h_out = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_out,
            layouter.namespace(|| "poseidon outer"),
        )?;
        let tag_out = layouter.assign_region(
            || "tag_out",
            |mut region| {
                let c = region.assign_advice(|| "tag_out", config.advice[5], 0, || Value::known(Fr::from(32u64)))?;
                region.constrain_constant(c.cell(), Fr::from(32u64))?;
                Ok(c)
            },
        )?;
        let digest = h_out.hash(
            layouter.namespace(|| "hash outer"),
            [tag_out, inner, nonce],
        )?;

        // 5) Bind digest to updated leaf: leaf_new must equal digest
        let leaf_new_again = layouter.assign_region(
            || "leaf_new_again",
            |mut region| region.assign_advice(|| "leaf_new_again", config.advice[4], 0, || self.leaf_new),
        )?;
        layouter.assign_region(
            || "bind digest to leaf_new",
            |mut region| {
                region.constrain_equal(leaf_new_cell.cell(), leaf_new_again.cell())?;
                region.constrain_equal(leaf_new_again.cell(), digest.cell())?;
                Ok(())
            },
        )?;

        // 6) Compute signature challenge and enforce simplified linear relation s = r + chal * pk
        // Challenge: chal = H(tag_sig, digest, pk)
        let chip_sig = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
        let h_sig = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_sig,
            layouter.namespace(|| "poseidon sig challenge"),
        )?;
        let tag_sig = layouter.assign_region(
            || "tag_sig",
            |mut region| region.assign_advice(|| "tag_sig", config.advice[5], 0, || Value::known(Fr::from(41u64))),
        )?;
        let chal = h_sig.hash(
            layouter.namespace(|| "hash(tag_sig,digest,pk)"),
            [tag_sig.clone(), digest.clone(), pk.clone()],
        )?;

        // Assign a row for the signature linear check and enable the selector
        layouter.assign_region(
            || "sig linear check row",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                // Reassign pk and enforce equality to previously assigned pk
                let pk_row = region.assign_advice(|| "pk_row", config.advice[0], 0, || self.payment_key)?;
                region.constrain_equal(pk_row.cell(), pk.cell())?;
                // Assign chal and constrain equal to computed chal
                let chal_val = chal.value().map(|x| *x);
                let chal_row = region.assign_advice(|| "chal_row", config.advice[1], 0, || chal_val)?;
                region.constrain_equal(chal_row.cell(), chal.cell())?;
                // Assign r and s from witnesses
                let _r_row = region.assign_advice(|| "sig_r", config.advice[2], 0, || self.sig_r)?;
                let _s_row = region.assign_advice(|| "sig_s", config.advice[3], 0, || self.sig_s)?;
                Ok(())
            },
        )?;

        // Expose public outputs
        layouter.constrain_instance(acc_after_cell.cell(), config.instance[0], 0)?;
        layouter.constrain_instance(digest.cell(), config.instance[1], 0)?;
        Ok(())
    }
}

/// Native digest helper mirroring the in-circuit composition
pub fn compute_tachy_digest(pk: Fr, value: Fr, nonce: Fr) -> Fr {
    use halo2_gadgets::poseidon::primitives as poseidon_primitives;
    let tag_in = Fr::from(31u64);
    let tag_out = Fr::from(32u64);
    let inner = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag_in, pk, value]);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag_out, inner, nonce])
}

/// Native helper to compute the signature challenge used in-circuit
pub fn compute_sig_challenge(digest: Fr, pk: Fr) -> Fr {
    use halo2_gadgets::poseidon::primitives as poseidon_primitives;
    let tag_sig = Fr::from(41u64);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([tag_sig, digest, pk])
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use crate::sparse_merkle::tests::native_hash;

    #[test]
    fn test_tachy_action_membership_and_digest() {
        const D: usize = 3;
        let leaf_old = Fr::from(7u64);
        let pk = Fr::from(123u64);
        let val = Fr::from(5u64);
        let nonce = Fr::from(77u64);
        let leaf_new = compute_tachy_digest(pk, val, nonce);
        let sibs = [Fr::from(2), Fr::from(3), Fr::from(5)];
        let dirs = [Fr::from(0), Fr::from(1), Fr::from(0)];

        let mut old_root = leaf_old;
        for i in 0..D {
            let d = dirs[i] != Fr::ZERO;
            let (x, y) = if !d { (old_root, sibs[i]) } else { (sibs[i], old_root) };
            old_root = native_hash(x, y);
        }
        let mut new_root = leaf_new;
        for i in 0..D {
            let d = dirs[i] != Fr::ZERO;
            let (x, y) = if !d { (new_root, sibs[i]) } else { (sibs[i], new_root) };
            new_root = native_hash(x, y);
        }

        let circuit = TachyActionCircuit::<D> {
            acc_root_before: Value::known(old_root),
            acc_root_after: Value::known(new_root),
            leaf_old: Value::known(leaf_old),
            leaf_new: Value::known(leaf_new),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
            payment_key: Value::known(pk),
            value: Value::known(val),
            nonce: Value::known(nonce),
            sig_r: {
                // choose r and derive s according to s = r + chal*pk
                let _chal = compute_sig_challenge(leaf_new, pk);
                let r = Fr::from(9u64);
                let _s = r + chal * pk;
                // store s in circuit field below; return r here
                Value::known(r)
            },
            sig_s: {
                let chal = compute_sig_challenge(leaf_new, pk);
                let r = Fr::from(9u64);
                let s = r + chal * pk;
                Value::known(s)
            },
        };
        let public_inputs = vec![vec![new_root], vec![leaf_new]]; // root, digest
        let prover = MockProver::run(12, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_tachy_action_wrong_pk_fails() {
        const D: usize = 3;
        let pk = Fr::from(123u64);
        let val = Fr::from(5u64);
        let nonce = Fr::from(77u64);
        let leaf_new = compute_tachy_digest(pk, val, nonce);
        let sibs = [Fr::from(2), Fr::from(3), Fr::from(5)];
        let dirs = [Fr::from(0), Fr::from(1), Fr::from(0)];
        let mut new_root = leaf_new;
        for i in 0..D {
            let d = dirs[i] != Fr::ZERO;
            let (x, y) = if !d { (new_root, sibs[i]) } else { (sibs[i], new_root) };
            new_root = native_hash(x, y);
        }
        let wrong_pk = Fr::from(999u64);
        let circuit = TachyActionCircuit::<D> {
            acc_root_before: Value::known(Fr::ZERO),
            acc_root_after: Value::known(new_root),
            leaf_old: Value::known(Fr::ZERO),
            leaf_new: Value::known(leaf_new),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
            payment_key: Value::known(wrong_pk),
            value: Value::known(val),
            nonce: Value::known(nonce),
            sig_r: {
                // Build signature using the correct pk, but witness wrong_pk; should fail
                let chal = compute_sig_challenge(leaf_new, pk);
                let r = Fr::from(9u64);
                Value::known(r)
            },
            sig_s: {
                let chal = compute_sig_challenge(leaf_new, pk);
                let r = Fr::from(9u64);
                let s = r + chal * pk; // uses true pk, circuit has wrong_pk
                Value::known(s)
            },
        };
        let prover = MockProver::run(12, &circuit, vec![vec![new_root], vec![leaf_new]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_tachy_action_wrong_sig_fails() {
        const D: usize = 3;
        let pk = Fr::from(123u64);
        let val = Fr::from(5u64);
        let nonce = Fr::from(77u64);
        let leaf_new = compute_tachy_digest(pk, val, nonce);
        let sibs = [Fr::from(2), Fr::from(3), Fr::from(5)];
        let dirs = [Fr::from(0), Fr::from(1), Fr::from(0)];
        let mut new_root = leaf_new;
        use crate::sparse_merkle::tests::native_hash;
        for i in 0..D {
            let d = dirs[i] != Fr::ZERO;
            let (x, y) = if !d { (new_root, sibs[i]) } else { (sibs[i], new_root) };
            new_root = native_hash(x, y);
        }
        let bad_s = Fr::from(999u64);
        let circuit = TachyActionCircuit::<D> {
            acc_root_before: Value::known(Fr::ZERO),
            acc_root_after: Value::known(new_root),
            leaf_old: Value::known(Fr::ZERO),
            leaf_new: Value::known(leaf_new),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
            payment_key: Value::known(pk),
            value: Value::known(val),
            nonce: Value::known(nonce),
            sig_r: Value::known(Fr::from(9u64)),
            sig_s: Value::known(bad_s),
        };
        let prover = MockProver::run(12, &circuit, vec![vec![new_root], vec![leaf_new]]).unwrap();
        assert!(prover.verify().is_err());
    }
}


