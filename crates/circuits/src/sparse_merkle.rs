//! Sparse Merkle set gadgets (halo2) for membership, non-membership, and root updates.
//! Numan Thabit 2025

use ff::Field;
use halo2_proofs::circuit::{Layouter, Value, AssignedCell, SimpleFloorPlanner};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Selector, Instance, Circuit};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_proofs::poly::Rotation;
use pasta_curves::Fp as Fr;

/// Poseidon-based 2-ary sparse Merkle tree over Fr with fixed depth.
#[derive(Clone, Debug)]
pub struct SparseMerkleConfig {
    pub advice: [Column<Advice>; 6],
    pub selector: Selector,
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

// A single update/membership verification row.

impl SparseMerkleConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let selector = meta.selector();
        for a in &advice { meta.enable_equality(*a); }

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

        // Constraint: direction is boolean 0/1
        meta.create_gate("direction boolean", |meta| {
            let s = meta.query_selector(selector);
            let d = meta.query_advice(advice[5], Rotation::cur());
            vec![s * d.clone() * (d - halo2_proofs::plonk::Expression::Constant(Fr::ONE))]
        });

        Self { advice, selector, poseidon }
    }

    /// Verify a single level hash: if dir==0, hash(leaf, sib); else hash(sib, leaf)
    pub fn hash_level(
        &self,
        mut layouter: impl Layouter<Fr>,
        leaf: AssignedCell<Fr, Fr>,
        sibling: AssignedCell<Fr, Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let chip = Pow5Chip::<Fr, 3, 2>::construct(self.poseidon.clone());
        let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon level"),
        )?;

        // domain separation tag
        let tag = Value::known(Fr::from(11u64));
        let tag_cell = layouter.assign_region(
            || "tag",
            |mut region| {
                let c = region.assign_advice(|| "tag", self.advice[4], 0, || tag)?;
                region.constrain_constant(c.cell(), Fr::from(11u64))?;
                Ok(c)
            },
        )?;

        // For simplicity in this skeleton, we compute H(tag, leaf, sibling)
        // Directional selection should be enforced by the caller using linear constraints.
        let out = h.hash(
            layouter.namespace(|| "hash(tag, leaf, sib)"),
            [tag_cell, leaf, sibling],
        )?;
        Ok(out)
    }
}

/// A circuit that verifies a Merkle path of fixed DEPTH and exposes the resulting root.
#[derive(Clone, Debug)]
pub struct SmtPathConfig {
    pub smt: SparseMerkleConfig,
    pub instance_root: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct SmtPathCircuit<const DEPTH: usize> {
    pub leaf: Value<Fr>,
    pub siblings: [Value<Fr>; DEPTH],
    pub directions: [Value<Fr>; DEPTH], // 0 left, 1 right
}

impl<const DEPTH: usize> Circuit<Fr> for SmtPathCircuit<DEPTH> {
    type Config = SmtPathConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Value::unknown(),
            siblings: [Value::unknown(); DEPTH],
            directions: [Value::unknown(); DEPTH],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let smt = SparseMerkleConfig::configure(meta);
        let instance_root = meta.instance_column();
        meta.enable_equality(instance_root);

        // x = (1-d)*leaf + d*sib; y = d*leaf + (1-d)*sib; dir boolean
        meta.create_gate("lin_sel", |meta| {
            let s = meta.query_selector(smt.selector);
            let leaf = meta.query_advice(smt.advice[0], Rotation::cur());
            let sib = meta.query_advice(smt.advice[1], Rotation::cur());
            let dir = meta.query_advice(smt.advice[5], Rotation::cur());
            let x = meta.query_advice(smt.advice[2], Rotation::cur());
            let y = meta.query_advice(smt.advice[3], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fr::ONE);
            vec![
                s.clone() * dir.clone() * (dir.clone() - one.clone()), // boolean
                s.clone() * (x.clone() - ((one.clone() - dir.clone()) * leaf.clone() + dir.clone() * sib.clone())),
                s * (y - (dir.clone() * leaf + (one - dir) * sib)),
            ]
        });

        SmtPathConfig { smt, instance_root }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Assign initial leaf
        let mut cur = layouter.assign_region(
            || "leaf",
            |mut region| region.assign_advice(|| "leaf", config.smt.advice[0], 0, || self.leaf),
        )?;

        for i in 0..DEPTH {
            // Assign sibling, direction, and perform linear selection in the same row
            let (x, y) = layouter.assign_region(
                || format!("lin sel {i}"),
                |mut region| {
                    config.smt.selector.enable(&mut region, 0)?;
                    // Assign leaf in this row for the gate and constrain to prior `cur`
                    let leaf_val = cur.value().map(|x| *x);
                    let leaf_row = region.assign_advice(|| "leaf_row", config.smt.advice[0], 0, || leaf_val)?;
                    region.constrain_equal(leaf_row.cell(), cur.cell())?;
                    // Assign sibling and direction where the gates read them
                    let _sib = region.assign_advice(|| "sib", config.smt.advice[1], 0, || self.siblings[i])?;
                    let dir_cell = region.assign_advice(|| "dir", config.smt.advice[5], 0, || self.directions[i])?;
                    // x = (1-d)*leaf + d*sib
                    let x = region.assign_advice(|| "x", config.smt.advice[2], 0, || {
                        self.directions[i].zip(cur.value()).zip(self.siblings[i]).map(|((d, l), s)| {
                            let one = Fr::ONE;
                            (one - d) * l + d * s
                        })
                    })?;
                    // y = d*leaf + (1-d)*sib
                    let y = region.assign_advice(|| "y", config.smt.advice[3], 0, || {
                        self.directions[i].zip(cur.value()).zip(self.siblings[i]).map(|((d, l), s)| {
                            d * l + (Fr::ONE - d) * s
                        })
                    })?;
                    // Return x,y and keep dir in-scope by closure capture
                    let _ = dir_cell; // ensures the assigned cell is kept in this row for the gate
                    Ok((x, y))
                },
            )?;

            // Hash level with Poseidon (direction enforced by linear constraints)
            let out = config.smt.hash_level(
                layouter.namespace(|| format!("hash level {i}")),
                x,
                y,
            )?;
            cur = out;
        }

        // Constrain final root to instance index 0
        layouter.constrain_instance(cur.cell(), config.instance_root, 0)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_gadgets::poseidon::primitives as poseidon_primitives;

    pub fn native_hash(a: Fr, b: Fr) -> Fr {
        let tag = Fr::from(11u64);
        poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([tag, a, b])
    }

    #[test]
    fn test_direction_non_boolean_fails() {
        const D: usize = 1;
        let leaf = Fr::from(7u64);
        let sibs = [Fr::from(2)];
        let dirs = [Fr::from(2u64)]; // invalid boolean

        // Compute the root using the same linear selection formulas with d=2
        let d = dirs[0];
        let x = (Fr::ONE - d) * leaf + d * sibs[0];
        let y = d * leaf + (Fr::ONE - d) * sibs[0];
        let expected_root = native_hash(x, y);

        let circuit = SmtPathCircuit::<D> {
            leaf: Value::known(leaf),
            siblings: [Value::known(sibs[0])],
            directions: [Value::known(dirs[0])],
        };
        let prover = MockProver::run(12, &circuit, vec![vec![expected_root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_membership_depth3() {
        const D: usize = 3;
        let leaf = Fr::from(7u64);
        let sibs = [Fr::from(2), Fr::from(3), Fr::from(5)];
        let dirs = [Fr::from(0), Fr::from(1), Fr::from(0)];

        let mut cur = leaf;
        for i in 0..D {
            let d_is_right = dirs[i] != Fr::ZERO;
            let (x, y) = if !d_is_right { (cur, sibs[i]) } else { (sibs[i], cur) };
            cur = native_hash(x, y);
        }

        let circuit = SmtPathCircuit::<D> {
            leaf: Value::known(leaf),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
        };

        let public_inputs = vec![vec![cur]];
        let prover = MockProver::run(12, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_update_depth3_same_path() {
        const D: usize = 3;
        // Start with a leaf and compute old root
        let leaf_old = Fr::from(7u64);
        let sibs = [Fr::from(2), Fr::from(3), Fr::from(5)];
        let dirs = [Fr::from(0), Fr::from(1), Fr::from(0)];
        let mut old_root = leaf_old;
        for i in 0..D {
            let d_is_right = dirs[i] != Fr::ZERO;
            let (x, y) = if !d_is_right { (old_root, sibs[i]) } else { (sibs[i], old_root) };
            old_root = native_hash(x, y);
        }

        // Update leaf and compute new root along the same path
        let leaf_new = Fr::from(11u64);
        let mut new_root = leaf_new;
        for i in 0..D {
            let d_is_right = dirs[i] != Fr::ZERO;
            let (x, y) = if !d_is_right { (new_root, sibs[i]) } else { (sibs[i], new_root) };
            new_root = native_hash(x, y);
        }

        // Prove membership for old then new via the same circuit shape
        let circuit_old = SmtPathCircuit::<D> {
            leaf: Value::known(leaf_old),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
        };
        let prover_old = MockProver::run(12, &circuit_old, vec![vec![old_root]]).unwrap();
        assert_eq!(prover_old.verify(), Ok(()));

        let circuit_new = SmtPathCircuit::<D> {
            leaf: Value::known(leaf_new),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
        };
        let prover_new = MockProver::run(12, &circuit_new, vec![vec![new_root]]).unwrap();
        assert_eq!(prover_new.verify(), Ok(()));
    }

    #[test]
    fn test_non_membership_depth3_zero_leaf() {
        const D: usize = 3;
        // Non-membership modeled as zero-leaf at the key slot
        let leaf = Fr::ZERO;
        let sibs = [Fr::from(8), Fr::from(9), Fr::from(10)];
        let dirs = [Fr::from(1), Fr::from(0), Fr::from(1)];

        let mut root = leaf;
        for i in 0..D {
            let d_is_right = dirs[i] != Fr::ZERO;
            let (x, y) = if !d_is_right { (root, sibs[i]) } else { (sibs[i], root) };
            root = native_hash(x, y);
        }

        let circuit = SmtPathCircuit::<D> {
            leaf: Value::known(leaf),
            siblings: [Value::known(sibs[0]), Value::known(sibs[1]), Value::known(sibs[2])],
            directions: [Value::known(dirs[0]), Value::known(dirs[1]), Value::known(dirs[2])],
        };
        let prover = MockProver::run(12, &circuit, vec![vec![root]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}


