# Tachyon Hash Chain - Quick Reference

## 🚀 Quick Start

```rust
use tachyon::*;
use curve25519_dalek::scalar::Scalar;

// 1. Setup
let params = Params::new(16, *b"MY_APP_V1_______________________", 1000);
let mut acc = init_accumulator(&params);
let mut fold = init_fold(&params, SBase::Zero);

// 2. Accumulate
let v = Scalar::from(42);
let roots = vec![Scalar::from(1), Scalar::from(2)];
let step = non_membership_step(&params, v, &acc, &fold, &roots)?;
acc = step.A_next;
fold = step.S_next;

// 3. Checkpoint
let checkpoint = create_checkpoint(&params, &acc, &fold);
```

## 📚 Core Types

| Type | Purpose | Size |
|------|---------|------|
| `Params` | Public parameters | ~8 KB (degree 256) |
| `Accumulator` | Chain A state | 40 bytes |
| `FoldState` | Chain S state | 40 bytes |
| `FoldStateWithCoeffs` | S with tracking | 40 + 32n bytes |
| `Checkpoint` | State snapshot | 104 bytes |

## 🔑 Key Functions

### Initialization
```rust
// Params: (max_degree, domain_separator[32], chain_id)
let params = Params::new(16, domain, chain_id);

// Initialize chains
let acc = init_accumulator(&params);
let fold = init_fold(&params, SBase::Zero);           // Commitment only
let fold = init_fold_with_coeffs(&params, SBase::Zero); // With coefficients
```

### Accumulation
```rust
// Commitment-only mode (constant memory)
let step = non_membership_step(&params, v, &acc, &fold, &roots)?;

// With coefficient tracking
let step = non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots)?;

// Update state
acc = step.A_next;
fold = step.S_next;
```

### Checkpointing
```rust
// Create
let checkpoint = create_checkpoint(&params, &acc, &fold);

// Verify
verify_checkpoint(&params, &checkpoint, &acc, &fold)?;

// Resume
let acc = resume_accumulator(&checkpoint);
let fold = resume_fold(&checkpoint);
```

## ⚠️ Error Handling

```rust
match non_membership_step(&params, v, &acc, &fold, &roots) {
    Ok(step) => { /* success */ },
    Err(TachyonError::DegreeExceeded { max, actual }) => { /* too many coefficients */ },
    Err(TachyonError::InvalidStepCounter { expected, actual }) => { /* desync */ },
    Err(TachyonError::CheckpointMismatch) => { /* bad checkpoint */ },
    Err(TachyonError::ChainBindingFailed) => { /* verification failed */ },
}
```

## 🔒 Security Features

| Feature | Protection Against |
|---------|-------------------|
| Chain Binding | Substitution attacks |
| Step Counter | Replay & truncation attacks |
| Chain ID | Cross-chain confusion |
| Degree Bounds | Overflow attacks |
| Domain Separation | Hash collision attacks |

## ⚡ Performance

| Operation | Time (est.) | Memory |
|-----------|-------------|---------|
| Step (commitment) | ~60 μs | 80 bytes |
| Step (coefficients) | ~100 μs | 80 + 32n bytes |
| Checkpoint create | ~2 μs | 104 bytes |
| Checkpoint verify | ~3 μs | 0 bytes |

## 🎯 Best Practices

### ✅ DO
```rust
// Unique chain ID per instance
let chain_id = rand::random::<u64>();

// Regular checkpoints (every 100-1000 steps)
if acc.step % 100 == 0 {
    let checkpoint = create_checkpoint(&params, &acc, &fold);
    save_checkpoint(&checkpoint)?;
}

// Always handle errors
let step = non_membership_step(...)
    .map_err(|e| log_error(e))?;

// Use commitment-only mode by default
let fold = init_fold(&params, SBase::Zero);
```

### ❌ DON'T
```rust
// DON'T reuse chain IDs
let params1 = Params::new(16, domain, 1000); // ❌
let params2 = Params::new(16, domain, 1000); // ❌ Same ID!

// DON'T ignore errors
let step = non_membership_step(...).unwrap(); // ❌

// DON'T use coefficients unless needed
let fold = init_fold_with_coeffs(...); // ❌ (if you don't need reveal)

// DON'T manually modify step counters
acc.step = 10; // ❌ Will cause validation errors
```

## 🔄 Common Patterns

### Pattern 1: Basic Accumulation Loop
```rust
for i in 0..num_steps {
    let roots = generate_roots(i);
    let step = non_membership_step(&params, v, &acc, &fold, &roots)?;
    acc = step.A_next;
    fold = step.S_next;
}
```

### Pattern 2: With Periodic Checkpoints
```rust
const CHECKPOINT_INTERVAL: u64 = 100;

for i in 0..num_steps {
    let roots = generate_roots(i);
    let step = non_membership_step(&params, v, &acc, &fold, &roots)?;
    acc = step.A_next;
    fold = step.S_next;
    
    if acc.step % CHECKPOINT_INTERVAL == 0 {
        let checkpoint = create_checkpoint(&params, &acc, &fold);
        save_checkpoint(&checkpoint)?;
    }
}
```

### Pattern 3: Reveal-Based Verification
```rust
let mut fold = init_fold_with_coeffs(&params, SBase::Zero);

for i in 0..num_steps {
    let roots = generate_roots(i);
    let step = non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots)?;
    acc = step.A_next;
    fold = step.S_next;
}

// Verify non-membership
if verify_non_membership_by_reveal(fold.coeffs(), v) {
    println!("✓ Non-membership proven!");
}
```

### Pattern 4: Recovery from Checkpoint
```rust
// Load checkpoint
let checkpoint = load_checkpoint()?;

// Resume chains
let mut acc = resume_accumulator(&checkpoint);
let mut fold = resume_fold(&checkpoint);

// Verify before continuing
verify_checkpoint(&params, &checkpoint, &acc, &fold)?;

// Continue accumulation
let step = non_membership_step(&params, v, &acc, &fold, &roots)?;
```

### Pattern 5: Parallel Independent Chains
```rust
let chain_a = create_chain(1000);
let chain_b = create_chain(2000);  // Different chain_id

// Chains are cryptographically isolated
process_chain_a(&chain_a, ...);
process_chain_b(&chain_b, ...);
```

## 🧪 Testing

```bash
# Run all tests
cargo test --lib tachygram

# Run specific test
cargo test --lib tachygram chain_binding_prevents_substitution

# Run with output
cargo test --lib tachygram -- --nocapture
```

## 📦 Serialization (Optional)

```toml
# Cargo.toml
[dependencies]
tachyon = { version = "2.0", features = ["serde"] }
```

```rust
use tachyon::{SerializableAccumulator, SerializableFoldState};

// Serialize
let ser_acc: SerializableAccumulator = acc.into();
let json = serde_json::to_string(&ser_acc)?;

// Deserialize
let de_acc: SerializableAccumulator = serde_json::from_str(&json)?;
let acc: Accumulator = de_acc.into();
```

## 🐛 Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `DegreeExceeded` | Too many coefficients | Reduce roots per step or increase max_degree |
| `InvalidStepCounter` | Desynchronized chains | Reload state from checkpoint |
| `CheckpointMismatch` | Checkpoint verification failed | Check checkpoint integrity |
| `ChainBindingFailed` | Chain state mismatch | Verify checkpoint source matches params |

## 📊 Capacity Planning

| Max Degree | Max Roots/Step | Param Size | Per-Step Size (coeff mode) |
|------------|----------------|------------|----------------------------|
| 16 | 16 | ~512 B | 40 + 512 B = 552 B |
| 64 | 64 | ~2 KB | 40 + 2 KB = 2088 B |
| 256 | 256 | ~8 KB | 40 + 8 KB = 8232 B |

**Recommendation**: Use degree 256 for production (flexibility vs. memory tradeoff)

## 🔗 Quick Links

- **Full Documentation**: [`TACHYGRAM_README.md`](TACHYGRAM_README.md)
- **Security Analysis**: [`HASH_CHAIN_IMPROVEMENTS.md`](HASH_CHAIN_IMPROVEMENTS.md)
- **Examples**: [`tachygram_example.rs`](tachygram_example.rs)
- **Implementation**: [`tachygram.rs`](tachygram.rs)

## 📝 Cheat Sheet

```rust
// Setup
let p = Params::new(16, domain, chain_id);
let mut a = init_accumulator(&p);
let mut f = init_fold(&p, SBase::Zero);

// Step
let s = non_membership_step(&p, v, &a, &f, &roots)?;
a = s.A_next; f = s.S_next;

// Checkpoint
let c = create_checkpoint(&p, &a, &f);
verify_checkpoint(&p, &c, &a, &f)?;

// Resume
let a = resume_accumulator(&c);
let f = resume_fold(&c);
```

---

**Version**: 2.0.0  
**Status**: Production Ready  
**Last Updated**: 2025-01-17

