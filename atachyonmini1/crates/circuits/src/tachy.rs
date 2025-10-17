//! Tachyactions: minimal spend/output circuit skeleton over Fr with accumulator-based verification and Poseidon digest.
//! Numan Thabit 2025
//! NOTE: Merkle tree verification removed - using accumulator-based approach for state updates.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;

#[derive(Clone, Debug)]
pub struct TachyConfig {
    pub advice: [Column<Advice>; 6],
    pub selector: Selector,
    pub instance: [Column<Instance>; 2], // 0: accumulator digest, 1: action digest
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

/// Tachyaction circuit: proves valid state transition via accumulator update
/// - Computes action digest from payment_key, value, nonce
/// - Updates accumulator state: acc' = H(acc, action_digest, counter)
/// - Proves ownership via simplified Schnorr-like signature
#[derive(Clone, Debug)]
pub struct TachyActionCircuit {
    pub acc_before: Value<Fr>,
    pub payment_key: Value<Fr>,
    pub value: Value<Fr>,
    pub nonce: Value<Fr>,
    pub counter: Value<Fr>,
    // Simplified Schnorr-like signature components over the base field
    pub sig_r: Value<Fr>,
    pub sig_s: Value<Fr>,
}

impl Circuit<Fr> for TachyActionCircuit {
    type Config = TachyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            acc_before: Value::unknown(),
            payment_key: Value::unknown(),
            value: Value::unknown(),
            nonce: Value::unknown(),
            counter: Value::unknown(),
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

        // Signature linear relation gate (toy-Schnorr over the field):
        // Enforce s = r + chal * pk in one row when selector is enabled.
        meta.create_gate("sig_linear_check", |meta| {
            let s = meta.query_selector(selector);
            let pk = meta.query_advice(advice[0], Rotation::cur());
            let chal = meta.query_advice(advice[1], Rotation::cur());
            let r = meta.query_advice(advice[2], Rotation::cur());
            let sig_s = meta.query_advice(advice[3], Rotation::cur());
            // Constraint: sig_s - (r + chal * pk) == 0
            vec![s * (sig_s - (r + chal * pk))]
        });

        TachyConfig { advice, selector, instance, poseidon }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 1) Compute action digest over (payment_key, value, nonce) via Poseidon with domain separation
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
        let action_digest = h_out.hash(
            layouter.namespace(|| "hash outer"),
            [tag_out, inner, nonce],
        )?;

        // 2) Update accumulator: acc_after = H(acc_before, action_digest, counter)
        let chip_acc = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
        let h_acc = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_acc,
            layouter.namespace(|| "poseidon accumulator"),
        )?;
        let acc_before_cell = layouter.assign_region(
            || "acc_before",
            |mut region| region.assign_advice(|| "acc_before", config.advice[4], 0, || self.acc_before),
        )?;
        let counter_cell = layouter.assign_region(
            || "counter",
            |mut region| region.assign_advice(|| "counter", config.advice[5], 0, || self.counter),
        )?;
        let acc_after = h_acc.hash(
            layouter.namespace(|| "hash accumulator"),
            [acc_before_cell.clone(), action_digest.clone(), counter_cell],
        )?;

        // 3) Compute signature challenge and enforce simplified linear relation s = r + chal * pk
        // Challenge: chal = H(tag_sig, action_digest, pk)
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
            [tag_sig.clone(), action_digest.clone(), pk.clone()],
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

        // Expose public outputs: [acc_after, action_digest]
        layouter.constrain_instance(acc_after.cell(), config.instance[0], 0)?;
        layouter.constrain_instance(action_digest.cell(), config.instance[1], 0)?;
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

/// Native helper to compute accumulator update: acc' = H(acc, action_digest, counter)
pub fn compute_acc_update(acc_before: Fr, action_digest: Fr, counter: u64) -> Fr {
    use halo2_gadgets::poseidon::primitives as poseidon_primitives;
    let counter_fr = Fr::from(counter);
    poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([acc_before, action_digest, counter_fr])
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

    #[test]
    fn test_tachy_action_accumulator_update() {
        let acc_before = Fr::from(42u64);
        let pk = Fr::from(123u64);
        let val = Fr::from(5u64);
        let nonce = Fr::from(77u64);
        let counter = 1u64;
        let action_digest = compute_tachy_digest(pk, val, nonce);
        let acc_after = compute_acc_update(acc_before, action_digest, counter);

        // Compute valid signature
        let chal = compute_sig_challenge(action_digest, pk);
        let r = Fr::from(9u64);
        let s = r + chal * pk;

        let circuit = TachyActionCircuit {
            acc_before: Value::known(acc_before),
            payment_key: Value::known(pk),
            value: Value::known(val),
            nonce: Value::known(nonce),
            counter: Value::known(Fr::from(counter)),
            sig_r: Value::known(r),
            sig_s: Value::known(s),
        };
        
        let public_inputs = vec![vec![acc_after], vec![action_digest]];
        let prover = MockProver::run(12, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_tachy_action_wrong_sig_fails() {
        let acc_before = Fr::from(42u64);
        let pk = Fr::from(123u64);
        let val = Fr::from(5u64);
        let nonce = Fr::from(77u64);
        let counter = 1u64;
        let action_digest = compute_tachy_digest(pk, val, nonce);
        let acc_after = compute_acc_update(acc_before, action_digest, counter);
        let bad_s = Fr::from(999u64);

        let circuit = TachyActionCircuit {
            acc_before: Value::known(acc_before),
            payment_key: Value::known(pk),
            value: Value::known(val),
            nonce: Value::known(nonce),
            counter: Value::known(Fr::from(counter)),
            sig_r: Value::known(Fr::from(9u64)),
            sig_s: Value::known(bad_s),
        };
        
        let prover = MockProver::run(12, &circuit, vec![vec![acc_after], vec![action_digest]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_tachy_action_chaining() {
        // Test chaining multiple tachyactions: acc1 = update(acc0, d1, 0), acc2 = update(acc1, d2, 1)
        let acc0 = Fr::ZERO;
        
        // First action (counter = 0)
        let pk1 = Fr::from(100u64);
        let d1 = compute_tachy_digest(pk1, Fr::from(10u64), Fr::from(1u64));
        let acc1 = compute_acc_update(acc0, d1, 0);
        
        // Second action (counter = 1)
        let pk2 = Fr::from(200u64);
        let d2 = compute_tachy_digest(pk2, Fr::from(20u64), Fr::from(2u64));
        let acc2 = compute_acc_update(acc1, d2, 1);
        
        // Verify chaining properties
        assert_ne!(acc0, acc1);
        assert_ne!(acc1, acc2);
        assert_ne!(acc0, acc2);
        
        // Verify determinism: recomputing gives same result
        let acc1_again = compute_acc_update(acc0, d1, 0);
        let acc2_again = compute_acc_update(acc1_again, d2, 1);
        assert_eq!(acc1, acc1_again);
        assert_eq!(acc2, acc2_again);
        
        // Verify counter matters: same digest with different counter gives different result
        let acc1_wrong_counter = compute_acc_update(acc0, d1, 1);
        assert_ne!(acc1, acc1_wrong_counter);
    }
}
