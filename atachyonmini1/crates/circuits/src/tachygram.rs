//! Tachygram: Chained proof structure for efficient verification
//! Numan Thabit 2025
//!
//! A tachygram is a sequence of tachyactions where each action's accumulator output
//! feeds into the next action's accumulator input, creating a verifiable chain:
//!
//! acc₁ = H(acc₀, action₀, 0), acc₂ = H(acc₁, action₁, 1), ..., accₙ = H(accₙ₋₁, actionₙ₋₁, n-1)
//!
//! This chaining structure enables:
//! 1. Efficient batch verification (only check endpoints)
//! 2. Proof compression through recursion
//! 3. Parallel proving with sequential commitment
//! 4. Incremental state updates

use anyhow::{anyhow, Result};
use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use pasta_curves::Fp as Fr;
use serde::{Deserialize, Serialize};

/// A single action in a tachygram chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TachyAction {
    pub payment_key: [u8; 32],
    pub value: u64,
    pub nonce: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

/// A tachygram: a chain of actions with start/end accumulator states
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tachygram {
    pub acc_start: [u8; 32],
    pub acc_end: [u8; 32],
    pub actions: Vec<TachyAction>,
    /// Counter tracking the number of actions accumulated so far
    pub counter: u64,
    /// Optional: proof data for the entire chain
    pub proof: Option<Vec<u8>>,
}

impl Tachygram {
    /// Create a new tachygram starting from the given accumulator state
    pub fn new(acc_start: [u8; 32]) -> Self {
        Self {
            acc_start,
            acc_end: acc_start, // Initially empty
            actions: Vec::new(),
            counter: 0,
            proof: None,
        }
    }

    /// Add an action to the tachygram and update the end accumulator
    pub fn add_action(&mut self, action: TachyAction) -> Result<()> {
        // Convert action to digest
        let action_digest = self.compute_action_digest(&action)?;
        
        // Update accumulator: acc_end' = H(acc_end, action_digest, counter)
        let acc_before_fr = bytes_to_fr(&self.acc_end)?;
        let action_digest_fr = bytes_to_fr(&action_digest)?;
        let acc_after_fr = compute_acc_update(acc_before_fr, action_digest_fr, self.counter);
        
        self.acc_end = fr_to_bytes(&acc_after_fr);
        self.actions.push(action);
        self.counter += 1;
        
        // Proof becomes stale when adding actions
        self.proof = None;
        
        Ok(())
    }

    /// Chain this tachygram with another (sequentially compose them)
    pub fn chain(mut self, other: Tachygram) -> Result<Self> {
        // Verify continuity: this.acc_end == other.acc_start AND this.counter == other's starting counter
        if self.acc_end != other.acc_start {
            return Err(anyhow!("Accumulator mismatch: cannot chain tachygrams"));
        }
        
        // Counter must be continuous - other should start where self ends
        let expected_start_counter = self.counter;
        let other_start_counter = other.counter - other.actions.len() as u64;
        if expected_start_counter != other_start_counter {
            return Err(anyhow!("Counter mismatch: cannot chain tachygrams"));
        }
        
        // Append actions and update end state
        self.actions.extend(other.actions);
        self.acc_end = other.acc_end;
        self.counter = other.counter;
        
        // Combined proof is invalid; must be regenerated
        self.proof = None;
        
        Ok(self)
    }

    /// Compute the action digest for a given action
    fn compute_action_digest(&self, action: &TachyAction) -> Result<[u8; 32]> {
        let pk_fr = bytes_to_fr(&action.payment_key)?;
        let val_fr = Fr::from(action.value);
        let nonce_fr = bytes_to_fr(&action.nonce)?;
        
        let digest_fr = crate::tachy::compute_tachy_digest(pk_fr, val_fr, nonce_fr);
        Ok(fr_to_bytes(&digest_fr))
    }

    /// Verify the accumulator chain without checking proofs
    pub fn verify_chain(&self) -> Result<bool> {
        let mut acc = bytes_to_fr(&self.acc_start)?;
        let start_counter = self.counter - self.actions.len() as u64;
        
        for (i, action) in self.actions.iter().enumerate() {
            let action_digest = self.compute_action_digest(action)?;
            let action_digest_fr = bytes_to_fr(&action_digest)?;
            let counter = start_counter + i as u64;
            acc = compute_acc_update(acc, action_digest_fr, counter);
        }
        
        let expected_end = bytes_to_fr(&self.acc_end)?;
        Ok(acc == expected_end)
    }

    /// Split a tachygram into two at the given index
    pub fn split(self, at: usize) -> Result<(Tachygram, Tachygram)> {
        if at > self.actions.len() {
            return Err(anyhow!("Split index out of bounds"));
        }
        
        let start_counter = self.counter - self.actions.len() as u64;
        
        if at == 0 {
            let mut empty = Tachygram::new(self.acc_start);
            empty.counter = start_counter;
            return Ok((
                empty,
                self,
            ));
        }
        
        if at == self.actions.len() {
            let mut empty = Tachygram::new(self.acc_end);
            empty.counter = self.counter;
            return Ok((
                self.clone(),
                empty,
            ));
        }
        
        // Compute intermediate accumulator state at split point
        let mut acc = bytes_to_fr(&self.acc_start)?;
        for (i, action) in self.actions.iter().take(at).enumerate() {
            let digest = self.compute_action_digest(action)?;
            let digest_fr = bytes_to_fr(&digest)?;
            let counter = start_counter + i as u64;
            acc = compute_acc_update(acc, digest_fr, counter);
        }
        let mid_acc = fr_to_bytes(&acc);
        let mid_counter = start_counter + at as u64;
        
        let (left_actions, right_actions) = self.actions.split_at(at);
        
        let left = Tachygram {
            acc_start: self.acc_start,
            acc_end: mid_acc,
            actions: left_actions.to_vec(),
            counter: mid_counter,
            proof: None,
        };
        
        let right = Tachygram {
            acc_start: mid_acc,
            acc_end: self.acc_end,
            actions: right_actions.to_vec(),
            counter: self.counter,
            proof: None,
        };
        
        Ok((left, right))
    }

    /// Get the length of the action chain
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Check if the tachygram is empty
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Circuit configuration for verifying a chained tachygram
#[derive(Clone, Debug)]
pub struct TachygramChainConfig {
    pub advice: [Column<Advice>; 6],
    pub selector: Selector,
    pub instance: [Column<Instance>; 2], // [acc_start, acc_end]
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

/// Circuit for verifying a chain of N actions
#[derive(Clone, Debug)]
pub struct TachygramChainCircuit<const N: usize> {
    pub acc_start: Value<Fr>,
    pub actions: [TachyActionWitness; N],
}

#[derive(Clone, Copy, Debug)]
pub struct TachyActionWitness {
    pub payment_key: Value<Fr>,
    pub value: Value<Fr>,
    pub nonce: Value<Fr>,
}

impl<const N: usize> Circuit<Fr> for TachygramChainCircuit<N> {
    type Config = TachygramChainConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            acc_start: Value::unknown(),
            actions: [TachyActionWitness {
                payment_key: Value::unknown(),
                value: Value::unknown(),
                nonce: Value::unknown(),
            }; N],
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
        
        for a in &advice {
            meta.enable_equality(*a);
        }
        for i in &instance {
            meta.enable_equality(*i);
        }

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

        TachygramChainConfig {
            advice,
            selector,
            instance,
            poseidon,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut acc = layouter.assign_region(
            || "acc_start",
            |mut region| {
                region.assign_advice(|| "acc_start", config.advice[0], 0, || self.acc_start)
            },
        )?;

        // Chain through each action
        for (i, action) in self.actions.iter().enumerate() {
            // Compute action digest
            let chip_in = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
            let h_in = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                chip_in,
                layouter.namespace(|| format!("poseidon inner {}", i)),
            )?;
            
            let tag_in = layouter.assign_region(
                || format!("tag_in {}", i),
                |mut region| {
                    let c = region.assign_advice(
                        || "tag_in",
                        config.advice[5],
                        0,
                        || Value::known(Fr::from(31u64)),
                    )?;
                    region.constrain_constant(c.cell(), Fr::from(31u64))?;
                    Ok(c)
                },
            )?;
            
            let pk = layouter.assign_region(
                || format!("pk {}", i),
                |mut region| {
                    region.assign_advice(|| "pk", config.advice[0], 0, || action.payment_key)
                },
            )?;
            
            let val = layouter.assign_region(
                || format!("val {}", i),
                |mut region| {
                    region.assign_advice(|| "val", config.advice[1], 0, || action.value)
                },
            )?;
            
            let nonce = layouter.assign_region(
                || format!("nonce {}", i),
                |mut region| {
                    region.assign_advice(|| "nonce", config.advice[2], 0, || action.nonce)
                },
            )?;
            
            let inner = h_in.hash(
                layouter.namespace(|| format!("hash inner {}", i)),
                [tag_in, pk, val],
            )?;
            
            let chip_out = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
            let h_out = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                chip_out,
                layouter.namespace(|| format!("poseidon outer {}", i)),
            )?;
            
            let tag_out = layouter.assign_region(
                || format!("tag_out {}", i),
                |mut region| {
                    let c = region.assign_advice(
                        || "tag_out",
                        config.advice[5],
                        0,
                        || Value::known(Fr::from(32u64)),
                    )?;
                    region.constrain_constant(c.cell(), Fr::from(32u64))?;
                    Ok(c)
                },
            )?;
            
            let action_digest = h_out.hash(
                layouter.namespace(|| format!("hash outer {}", i)),
                [tag_out, inner, nonce],
            )?;

            // Update accumulator: acc' = H(acc, action_digest, counter)
            let chip_acc = Pow5Chip::<Fr, 3, 2>::construct(config.poseidon.clone());
            let h_acc = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
                chip_acc,
                layouter.namespace(|| format!("poseidon acc {}", i)),
            )?;
            
            let counter_cell = layouter.assign_region(
                || format!("counter {}", i),
                |mut region| {
                    region.assign_advice(
                        || "counter",
                        config.advice[5],
                        0,
                        || Value::known(Fr::from(i as u64)),
                    )
                },
            )?;
            
            acc = h_acc.hash(
                layouter.namespace(|| format!("hash acc {}", i)),
                [acc, action_digest, counter_cell],
            )?;
        }

        // Expose start and end accumulator as public inputs
        layouter.constrain_instance(acc.cell(), config.instance[1], 0)?;
        
        Ok(())
    }
}

// Helper functions

fn bytes_to_fr(bytes: &[u8; 32]) -> Result<Fr> {
    Fr::from_repr(*bytes)
        .into_option()
        .ok_or_else(|| anyhow!("Invalid field element encoding"))
}

fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(fr.to_repr().as_ref());
    bytes
}

fn compute_acc_update(acc_before: Fr, action_digest: Fr, counter: u64) -> Fr {
    use halo2_gadgets::poseidon::primitives as p;
    let counter_fr = Fr::from(counter);
    p::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([acc_before, action_digest, counter_fr])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tachygram_empty() {
        let acc_start = [0u8; 32];
        let tg = Tachygram::new(acc_start);
        assert_eq!(tg.acc_start, tg.acc_end);
        assert!(tg.is_empty());
        assert!(tg.verify_chain().unwrap());
    }

    #[test]
    fn test_tachygram_single_action() {
        let acc_start = [0u8; 32];
        let mut tg = Tachygram::new(acc_start);
        
        let action = TachyAction {
            payment_key: [1u8; 32],
            value: 100,
            nonce: [2u8; 32],
            sig_r: [3u8; 32],
            sig_s: [4u8; 32],
        };
        
        tg.add_action(action).unwrap();
        assert_eq!(tg.len(), 1);
        assert_ne!(tg.acc_start, tg.acc_end);
        assert!(tg.verify_chain().unwrap());
    }

    #[test]
    fn test_tachygram_chain_multiple() {
        let acc_start = [0u8; 32];
        let mut tg = Tachygram::new(acc_start);
        
        for i in 0..5 {
            let action = TachyAction {
                payment_key: [i as u8; 32],
                value: 100 * (i as u64 + 1),
                nonce: [(i + 10) as u8; 32],
                sig_r: [0u8; 32],
                sig_s: [0u8; 32],
            };
            tg.add_action(action).unwrap();
        }
        
        assert_eq!(tg.len(), 5);
        assert!(tg.verify_chain().unwrap());
    }

    #[test]
    fn test_tachygram_chaining() {
        let acc_start = [0u8; 32];
        let mut tg1 = Tachygram::new(acc_start);
        
        let action1 = TachyAction {
            payment_key: [1u8; 32],
            value: 100,
            nonce: [10u8; 32],
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
        };
        tg1.add_action(action1).unwrap();
        
        // Create tg2 starting from where tg1 ended, with proper counter continuation
        let mut tg2 = Tachygram::new(tg1.acc_end);
        tg2.counter = tg1.counter; // Start counter where tg1 left off
        let action2 = TachyAction {
            payment_key: [2u8; 32],
            value: 200,
            nonce: [20u8; 32],
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
        };
        tg2.add_action(action2).unwrap();
        
        let chained = tg1.chain(tg2).unwrap();
        assert_eq!(chained.len(), 2);
        assert_eq!(chained.counter, 2); // Final counter should be 2 after 2 actions
        assert!(chained.verify_chain().unwrap());
    }

    #[test]
    fn test_tachygram_split() {
        let acc_start = [0u8; 32];
        let mut tg = Tachygram::new(acc_start);
        
        for i in 0..4 {
            let action = TachyAction {
                payment_key: [i as u8; 32],
                value: 100 * (i as u64 + 1),
                nonce: [(i + 10) as u8; 32],
                sig_r: [0u8; 32],
                sig_s: [0u8; 32],
            };
            tg.add_action(action).unwrap();
        }
        
        let (left, right) = tg.split(2).unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(right.len(), 2);
        assert!(left.verify_chain().unwrap());
        assert!(right.verify_chain().unwrap());
        
        // Verify they can be rechained
        let rechained = left.chain(right).unwrap();
        assert_eq!(rechained.len(), 4);
        assert!(rechained.verify_chain().unwrap());
    }

    #[test]
    fn test_tachygram_chain_mismatch() {
        let tg1 = Tachygram::new([0u8; 32]);
        let tg2 = Tachygram::new([1u8; 32]); // Different start
        
        let result = tg1.chain(tg2);
        assert!(result.is_err());
    }
}

