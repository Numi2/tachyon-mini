//! Property-based tests for circuits using proptest
//! Numan Thabit 2025

use circuits::{compute_tachy_digest, tachy::*,  tachygram::*};
use ff::Field;
use pasta_curves::Fp as Fr;
use proptest::prelude::*;

// Strategy for generating valid field elements
fn fr_strategy() -> impl Strategy<Value = Fr> {
    any::<u64>().prop_map(Fr::from)
}

// Strategy for generating tachygrams
fn tachygram_strategy() -> impl Strategy<Value = Tachygram> {
    (any::<[u8; 32]>(), prop::collection::vec(action_strategy(), 0..10)).prop_map(
        |(acc_start, actions)| {
            let mut tg = Tachygram::new(acc_start);
            for action in actions {
                let _ = tg.add_action(action);
            }
            tg
        },
    )
}

fn action_strategy() -> impl Strategy<Value = TachyAction> {
    (
        any::<[u8; 32]>(),
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
    )
        .prop_map(|(pk, value, nonce, sig_r, sig_s)| TachyAction {
            payment_key: pk,
            value,
            nonce,
            sig_r,
            sig_s,
        })
}

proptest! {
    #[test]
    fn test_tachy_digest_deterministic(pk in fr_strategy(), value in fr_strategy(), nonce in fr_strategy()) {
        // Property: Computing digest twice with same inputs gives same result
        let digest1 = compute_tachy_digest(pk, value, nonce);
        let digest2 = compute_tachy_digest(pk, value, nonce);
        prop_assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_tachy_digest_different_inputs(
        pk1 in fr_strategy(),
        pk2 in fr_strategy(),
        value in fr_strategy(),
        nonce in fr_strategy(),
    ) {
        // Property: Different payment keys should produce different digests (with high probability)
        prop_assume!(pk1 != pk2);
        let digest1 = compute_tachy_digest(pk1, value, nonce);
        let digest2 = compute_tachy_digest(pk2, value, nonce);
        prop_assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_acc_update_deterministic(
        acc_before in fr_strategy(),
        action_digest in fr_strategy(),
        counter in any::<u64>(),
    ) {
        // Property: Accumulator updates are deterministic
        let acc1 = compute_acc_update(acc_before, action_digest, counter);
        let acc2 = compute_acc_update(acc_before, action_digest, counter);
        prop_assert_eq!(acc1, acc2);
    }

    #[test]
    fn test_acc_update_changes_state(
        acc_before in fr_strategy(),
        action_digest in fr_strategy(),
        counter in any::<u64>(),
    ) {
        // Property: Accumulator update should change state (unless both inputs are zero)
        let acc_after = compute_acc_update(acc_before, action_digest, counter);
        // State changes unless all meaningful inputs are zero
        if action_digest != Fr::ZERO || counter != 0 || acc_before != Fr::ZERO {
            prop_assert_ne!(acc_before, acc_after);
        }
    }

    #[test]
    fn test_sig_challenge_deterministic(
        digest in fr_strategy(),
        pk in fr_strategy(),
    ) {
        // Property: Signature challenge computation is deterministic
        let chal1 = compute_sig_challenge(digest, pk);
        let chal2 = compute_sig_challenge(digest, pk);
        prop_assert_eq!(chal1, chal2);
    }

    #[test]
    fn test_tachygram_verify_chain(tg in tachygram_strategy()) {
        // Property: A properly constructed tachygram should always verify
        prop_assert!(tg.verify_chain().unwrap());
    }

    #[test]
    fn test_tachygram_chaining_associative(
        tg1 in tachygram_strategy(),
        tg2 in tachygram_strategy(),
        tg3 in tachygram_strategy(),
    ) {
        // Property: Chaining is associative (when continuity is preserved)
        // (tg1 + tg2) + tg3 == tg1 + (tg2 + tg3)
        
        // Make tg2 start where tg1 ends (with proper counter continuity)
        let mut tg2_adjusted = tg2.clone();
        tg2_adjusted.acc_start = tg1.acc_end;
        tg2_adjusted.counter = tg1.counter; // Continue counter from tg1
        // Recompute end state for tg2_adjusted
        let _ = tg2_adjusted.verify_chain();
        
        // Make tg3 start where tg2_adjusted ends (with proper counter continuity)
        let mut tg3_adjusted = tg3.clone();
        tg3_adjusted.acc_start = tg2_adjusted.acc_end;
        tg3_adjusted.counter = tg2_adjusted.counter; // Continue counter from tg2_adjusted
        // Recompute end state for tg3_adjusted
        let _ = tg3_adjusted.verify_chain();
        
        // Chain left-to-right: (tg1 + tg2) + tg3
        let left = tg1.clone().chain(tg2_adjusted.clone()).unwrap().chain(tg3_adjusted.clone()).unwrap();
        
        // Chain with different grouping: tg1 + (tg2 + tg3)
        let right_inner = tg2_adjusted.clone().chain(tg3_adjusted.clone()).unwrap();
        let right = tg1.clone().chain(right_inner).unwrap();
        
        prop_assert_eq!(left.acc_start, right.acc_start);
        prop_assert_eq!(left.acc_end, right.acc_end);
        prop_assert_eq!(left.len(), right.len());
    }

    #[test]
    fn test_tachygram_split_preserves_length(tg in tachygram_strategy(), split_at in 0usize..10) {
        // Property: Splitting a tachygram preserves total length
        let len = tg.len();
        if split_at <= len {
            let (left, right) = tg.split(split_at).unwrap();
            prop_assert_eq!(left.len() + right.len(), len);
            
            // Both parts should verify
            prop_assert!(left.verify_chain().unwrap());
            prop_assert!(right.verify_chain().unwrap());
            
            // They should be rechainable
            let rechained = left.chain(right).unwrap();
            prop_assert_eq!(rechained.len(), len);
            prop_assert!(rechained.verify_chain().unwrap());
        }
    }

    #[test]
    fn test_tachygram_empty_is_identity(tg in tachygram_strategy()) {
        // Property: Chaining with an empty tachygram is identity
        let mut empty = Tachygram::new(tg.acc_end);
        empty.counter = tg.counter; // Set counter to continue from tg
        let chained = tg.clone().chain(empty).unwrap();
        
        prop_assert_eq!(chained.acc_start, tg.acc_start);
        prop_assert_eq!(chained.acc_end, tg.acc_end);
        prop_assert_eq!(chained.len(), tg.len());
    }
}

#[cfg(test)]
mod invariants {
    use super::*;

    proptest! {
        #[test]
        fn test_accumulator_never_zero_unless_all_zero(
            acc in fr_strategy(),
            digest in fr_strategy(),
            counter in any::<u64>(),
        ) {
            // Property: If any input is non-zero, output should be non-zero
            let result = compute_acc_update(acc, digest, counter);
            if acc != Fr::ZERO || digest != Fr::ZERO || counter != 0 {
                prop_assert_ne!(result, Fr::ZERO);
            }
        }

        #[test]
        fn test_accumulator_collision_resistance(
            acc in fr_strategy(),
            d1 in fr_strategy(),
            d2 in fr_strategy(),
            counter in any::<u64>(),
        ) {
            // Property: Different digests should produce different accumulator states (collision resistance)
            prop_assume!(d1 != d2);
            let r1 = compute_acc_update(acc, d1, counter);
            let r2 = compute_acc_update(acc, d2, counter);
            prop_assert_ne!(r1, r2);
        }
        
        #[test]
        fn test_counter_matters(
            acc in fr_strategy(),
            digest in fr_strategy(),
            c1 in any::<u64>(),
            c2 in any::<u64>(),
        ) {
            // Property: Different counters should produce different accumulator states
            prop_assume!(c1 != c2);
            let r1 = compute_acc_update(acc, digest, c1);
            let r2 = compute_acc_update(acc, digest, c2);
            prop_assert_ne!(r1, r2);
        }
    }
}

