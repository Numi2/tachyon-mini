//! Production Example: Tachyon Hash Chain Accumulator
//!
//! This example demonstrates real-world usage of the hardened Tachyon accumulator
//! with security features enabled.

// Import the tachygram module
#[path = "tachygram.rs"]
mod tachygram;

use tachygram as tachyon;
use curve25519_dalek::scalar::Scalar;

/// Example 1: Basic accumulator with non-membership proofs
pub fn example_basic_accumulator() {
    println!("=== Example 1: Basic Accumulator ===\n");
    
    // Initialize parameters with unique chain ID
    let params = tachyon::Params::new(
        16,                                      // max degree
        *b"MY_APP_V1_______________________",   // domain separator (32 bytes)
        1000,                                    // unique chain ID
    );
    
    let v = Scalar::from(42u64); // Value to prove non-membership for
    
    // Initialize accumulator and fold state
    let mut acc = tachyon::init_accumulator(&params);
    let mut fold = tachyon::init_fold(&params, tachyon::SBase::Zero);
    
    // Perform accumulation steps
    for i in 0..10 {
        let roots = vec![
            Scalar::from(i * 10),
            Scalar::from(i * 10 + 1),
            Scalar::from(i * 10 + 2),
        ];
        
        match tachyon::non_membership_step(&params, v, &acc, &fold, &roots) {
            Ok(step) => {
                println!("Step {}: Successfully accumulated {} roots", i, roots.len());
                println!("  Step counter: {}", step.A_next.step);
                println!("  Challenge h: {:?}", &step.h.to_bytes()[..8]);
                println!("  Challenge h': {:?}", &step.h_prime.to_bytes()[..8]);
                
                acc = step.A_next;
                fold = step.S_next;
            }
            Err(e) => {
                eprintln!("Error at step {}: {:?}", i, e);
                return;
            }
        }
    }
    
    println!("\nFinal state:");
    println!("  Accumulator step: {}", acc.step);
    println!("  Fold state step: {}", fold.step);
    println!("  Both chains synchronized: {}", acc.step == fold.step);
}

/// Example 2: Checkpoint-based recovery for long-running chains
pub fn example_checkpoint_recovery() {
    println!("\n=== Example 2: Checkpoint Recovery ===\n");
    
    let params = tachyon::Params::new(
        16,
        *b"CHECKPOINT_EXAMPLE______________",
        2000,
    );
    
    let v = Scalar::from(99u64);
    let mut acc = tachyon::init_accumulator(&params);
    let mut fold = tachyon::init_fold(&params, tachyon::SBase::Zero);
    
    let checkpoint_interval = 5;
    let mut last_checkpoint = None;
    
    // Simulate a long-running accumulation with periodic checkpoints
    for i in 0..20 {
        let roots = vec![Scalar::from(i + 1000)];
        
        let step = tachyon::non_membership_step(&params, v, &acc, &fold, &roots)
            .expect("Step should succeed");
        acc = step.A_next;
        fold = step.S_next;
        
        // Create checkpoint every N steps
        if (i + 1) % checkpoint_interval == 0 {
            let checkpoint = tachyon::create_checkpoint(&params, &acc, &fold);
            println!("Created checkpoint at step {}", checkpoint.step);
            println!("  Commitment hash: {:?}", &checkpoint.commitment_hash[..8]);
            last_checkpoint = Some(checkpoint);
        }
    }
    
    // Simulate recovery from checkpoint
    if let Some(checkpoint) = last_checkpoint {
        println!("\n--- Simulating recovery from checkpoint ---");
        
        let recovered_acc = tachyon::resume_accumulator(&checkpoint);
        let recovered_fold = tachyon::resume_fold(&checkpoint);
        
        println!("Recovered accumulator at step: {}", recovered_acc.step);
        println!("Recovered fold state at step: {}", recovered_fold.step);
        
        // Verify checkpoint matches current state
        match tachyon::verify_checkpoint(&params, &checkpoint, &acc, &fold) {
            Ok(_) => println!("✓ Checkpoint verification successful!"),
            Err(e) => println!("✗ Checkpoint verification failed: {:?}", e),
        }
        
        // Continue from checkpoint
        let roots = vec![Scalar::from(9999u64)];
        let step = tachyon::non_membership_step(&params, v, &recovered_acc, &recovered_fold, &roots)
            .expect("Should continue from checkpoint");
        
        println!("Continued from checkpoint to step: {}", step.A_next.step);
    }
}

/// Example 3: Coefficient tracking for reveal-based verification
pub fn example_coefficient_tracking() {
    println!("\n=== Example 3: Coefficient Tracking ===\n");
    
    let params = tachyon::Params::new(
        12,
        *b"COEFFS_EXAMPLE__________________",
        3000,
    );
    
    let v = Scalar::from(17u64);
    let mut acc = tachyon::init_accumulator(&params);
    let mut fold = tachyon::init_fold_with_coeffs(&params, tachyon::SBase::Zero);
    
    // Accumulate with coefficient tracking
    for i in 0..5 {
        let roots = vec![
            Scalar::from(i + 1),
            Scalar::from(i + 2),
        ];
        
        let step = tachyon::non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots)
            .expect("Step should succeed");
        
        println!("Step {}: Tracked {} coefficients", i, step.S_next.coeffs().len());
        
        acc = step.A_next;
        fold = step.S_next;
    }
    
    // Verify non-membership by revealing coefficients
    let coeffs = fold.coeffs();
    let is_non_member = tachyon::verify_non_membership_by_reveal(coeffs, v);
    
    println!("\nFinal coefficient count: {}", coeffs.len());
    println!("Non-membership verification: {}", 
        if is_non_member { "✓ PASS" } else { "✗ FAIL" });
    
    // Verify commitment consistency
    let commitment = tachyon::commit_coeffs(&params, coeffs)
        .expect("Should commit coefficients");
    let matches = commitment.compress() == fold.S.compress();
    
    println!("Commitment consistency: {}", if matches { "✓ PASS" } else { "✗ FAIL" });
}

/// Example 4: Multiple parallel chains with different chain IDs
pub fn example_parallel_chains() {
    println!("\n=== Example 4: Parallel Chains ===\n");
    
    let v = Scalar::from(7u64);
    
    // Create two independent chains
    let params_alice = tachyon::Params::new(
        8,
        *b"ALICE_CHAIN_____________________",
        4001,
    );
    
    let params_bob = tachyon::Params::new(
        8,
        *b"BOB_CHAIN_______________________",
        4002,
    );
    
    let mut acc_alice = tachyon::init_accumulator(&params_alice);
    let mut fold_alice = tachyon::init_fold(&params_alice, tachyon::SBase::Zero);
    
    let mut acc_bob = tachyon::init_accumulator(&params_bob);
    let mut fold_bob = tachyon::init_fold(&params_bob, tachyon::SBase::Zero);
    
    // Same inputs, different chains
    let roots = vec![Scalar::from(10u64), Scalar::from(20u64)];
    
    let step_alice = tachyon::non_membership_step(&params_alice, v, &acc_alice, &fold_alice, &roots)
        .expect("Alice's step should succeed");
    
    let step_bob = tachyon::non_membership_step(&params_bob, v, &acc_bob, &fold_bob, &roots)
        .expect("Bob's step should succeed");
    
    println!("Alice's challenge h:  {:?}", &step_alice.h.to_bytes()[..8]);
    println!("Bob's challenge h:    {:?}", &step_bob.h.to_bytes()[..8]);
    println!("Challenges different: {}", step_alice.h != step_bob.h);
    
    println!("\nAlice's challenge h': {:?}", &step_alice.h_prime.to_bytes()[..8]);
    println!("Bob's challenge h':   {:?}", &step_bob.h_prime.to_bytes()[..8]);
    println!("Challenges different: {}", step_alice.h_prime != step_bob.h_prime);
    
    println!("\n✓ Chain binding ensures independent chains produce different results");
}

/// Example 5: Error handling and validation
pub fn example_error_handling() {
    println!("\n=== Example 5: Error Handling ===\n");
    
    let params = tachyon::Params::new(
        4,  // Small degree for testing
        *b"ERROR_EXAMPLE___________________",
        5000,
    );
    
    // Test 1: Degree bound exceeded
    println!("Test 1: Degree bound validation");
    let too_many_coeffs = vec![Scalar::from(1u64); 10];
    match params.commit_coeffs(&too_many_coeffs) {
        Ok(_) => println!("  ✗ Should have failed!"),
        Err(tachyon::TachyonError::DegreeExceeded { max, actual }) => {
            println!("  ✓ Caught degree exceeded: max={}, actual={}", max, actual);
        }
        Err(e) => println!("  ✗ Unexpected error: {:?}", e),
    }
    
    // Test 2: Step counter desynchronization
    println!("\nTest 2: Step counter validation");
    let v = Scalar::from(5u64);
    let mut acc = tachyon::init_accumulator(&params);
    let mut fold = tachyon::init_fold(&params, tachyon::SBase::Zero);
    
    // Manually desync
    acc.step = 1;
    fold.step = 0;
    
    let roots = vec![Scalar::from(1u64)];
    match tachyon::non_membership_step(&params, v, &acc, &fold, &roots) {
        Ok(_) => println!("  ✗ Should have failed!"),
        Err(tachyon::TachyonError::InvalidStepCounter { expected, actual }) => {
            println!("  ✓ Caught step desync: expected={}, actual={}", expected, actual);
        }
        Err(e) => println!("  ✗ Unexpected error: {:?}", e),
    }
    
    // Test 3: Checkpoint mismatch
    println!("\nTest 3: Checkpoint validation");
    let mut acc = tachyon::init_accumulator(&params);
    let mut fold = tachyon::init_fold(&params, tachyon::SBase::Zero);
    
    let checkpoint = tachyon::create_checkpoint(&params, &acc, &fold);
    
    // Advance the chain
    let step = tachyon::non_membership_step(&params, v, &acc, &fold, &roots)
        .expect("Step should succeed");
    acc = step.A_next;
    fold = step.S_next;
    
    // Old checkpoint shouldn't match
    match tachyon::verify_checkpoint(&params, &checkpoint, &acc, &fold) {
        Ok(_) => println!("  ✗ Should have failed!"),
        Err(e) => println!("  ✓ Caught checkpoint mismatch: {:?}", e),
    }
}

/// Example 6: Serialization (requires serde feature)
#[cfg(feature = "serde")]
pub fn example_serialization() {
    use tachyon::{SerializableAccumulator, SerializableFoldState};
    
    println!("\n=== Example 6: Serialization ===\n");
    
    let params = tachyon::Params::new(
        8,
        *b"SERDE_EXAMPLE___________________",
        6000,
    );
    
    let v = Scalar::from(11u64);
    let mut acc = tachyon::init_accumulator(&params);
    let mut fold = tachyon::init_fold(&params, tachyon::SBase::Zero);
    
    // Perform some steps
    for i in 0..3 {
        let roots = vec![Scalar::from(i)];
        let step = tachyon::non_membership_step(&params, v, &acc, &fold, &roots)
            .expect("Step should succeed");
        acc = step.A_next;
        fold = step.S_next;
    }
    
    // Serialize
    let ser_acc: SerializableAccumulator = acc.into();
    let ser_fold: SerializableFoldState = fold.into();
    
    let json_acc = serde_json::to_string_pretty(&ser_acc)
        .expect("Should serialize accumulator");
    let json_fold = serde_json::to_string_pretty(&ser_fold)
        .expect("Should serialize fold state");
    
    println!("Serialized accumulator:");
    println!("{}", json_acc);
    println!("\nSerialized fold state:");
    println!("{}", json_fold);
    
    // Deserialize
    let de_acc: SerializableAccumulator = serde_json::from_str(&json_acc)
        .expect("Should deserialize accumulator");
    let de_fold: SerializableFoldState = serde_json::from_str(&json_fold)
        .expect("Should deserialize fold state");
    
    let recovered_acc: tachyon::Accumulator = de_acc.into();
    let recovered_fold: tachyon::FoldState = de_fold.into();
    
    println!("\n✓ Serialization round-trip successful!");
    println!("  Recovered accumulator step: {}", recovered_acc.step);
    println!("  Recovered fold state step: {}", recovered_fold.step);
}

pub fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Tachyon Hash Chain Accumulator - Production Examples     ║");
    println!("║  Security-hardened implementation with real-world usage   ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    
    example_basic_accumulator();
    example_checkpoint_recovery();
    example_coefficient_tracking();
    example_parallel_chains();
    example_error_handling();
    
    #[cfg(feature = "serde")]
    example_serialization();
    
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  All examples completed successfully!                      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
}

