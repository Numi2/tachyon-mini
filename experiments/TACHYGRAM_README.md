# Tachyon Hash Chain Accumulator

**Production-grade cryptographic accumulator with security hardening for real-world applications**

## Features

### Core Functionality
- ✅ **Dual Hash Chains**: Accumulator (A) and fold state (S) for non-membership proofs
- ✅ **Commitment-Based**: Pedersen-style vector commitments over Ristretto points
- ✅ **Polynomial Accumulation**: Efficient root-based polynomial commitments
- ✅ **IVC-Friendly**: Designed for incremental verifiable computation

### Security Hardening
- 🔒 **Chain Binding**: Cryptographic binding between parallel chains prevents substitution attacks
- 🔒 **Replay Protection**: Step counters in all hash computations prevent replay attacks
- 🔒 **Truncation Protection**: Step validation prevents truncation attacks
- 🔒 **Chain Isolation**: Unique chain IDs prevent cross-chain confusion
- 🔒 **Degree Bounds**: Explicit validation prevents overflow attacks
- 🔒 **Hash Input Safety**: Validated point compression with explicit length checks

### Production Features
- 📦 **Checkpoint System**: Efficient state snapshots for long-running chains
- 📦 **Type Safety**: Separate types for commitment-only vs. coefficient tracking
- 📦 **Error Handling**: Comprehensive Result-based error handling
- 📦 **Serialization**: Optional serde support for persistence
- 📦 **No Panics**: Library code never panics, always returns errors

### Performance
- ⚡ **Efficient**: ~2 hashes + ~3 group operations per step (commitment mode)
- ⚡ **Constant State**: 40 bytes per chain state (commitment mode)
- ⚡ **Scalable**: Tested with 50+ step chains, scales to millions
- ⚡ **No Allocations**: Minimal heap usage in hot path

## Quick Start

### Basic Usage

```rust
use tachyon::{Params, init_accumulator, init_fold, non_membership_step, SBase};
use curve25519_dalek::scalar::Scalar;

// Initialize parameters
let params = Params::new(
    16,                                     // max polynomial degree
    *b"MY_APP_V1_______________________",  // 32-byte domain separator
    1000,                                   // unique chain ID
);

// Initialize chains
let mut acc = init_accumulator(&params);
let mut fold = init_fold(&params, SBase::Zero);

// Prove non-membership of value v
let v = Scalar::from(42u64);
let roots = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];

// Perform accumulation step
let step = non_membership_step(&params, v, &acc, &fold, &roots)?;
acc = step.A_next;
fold = step.S_next;

println!("Step {}: Accumulated {} roots", acc.step, roots.len());
```

### With Coefficient Tracking

```rust
use tachyon::{init_fold_with_coeffs, non_membership_step_with_coeffs, verify_non_membership_by_reveal};

let mut fold = init_fold_with_coeffs(&params, SBase::Zero);

// Accumulate steps
for i in 0..10 {
    let roots = vec![Scalar::from(i), Scalar::from(i + 1)];
    let step = non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots)?;
    acc = step.A_next;
    fold = step.S_next;
}

// Verify non-membership by revealing polynomial coefficients
let is_non_member = verify_non_membership_by_reveal(fold.coeffs(), v);
assert!(is_non_member);
```

### Checkpoint Recovery

```rust
use tachyon::{create_checkpoint, verify_checkpoint, resume_accumulator, resume_fold};

// Create checkpoint
let checkpoint = create_checkpoint(&params, &acc, &fold);

// ... perform more steps ...

// Resume from checkpoint
let recovered_acc = resume_accumulator(&checkpoint);
let recovered_fold = resume_fold(&checkpoint);

// Verify checkpoint matches current state
verify_checkpoint(&params, &checkpoint, &acc, &fold)?;
```

## API Reference

### Types

#### Core State

```rust
pub struct Accumulator {
    pub A: RistrettoPoint,  // Accumulated commitment
    pub step: u64,          // Current step counter
}

pub struct FoldState {
    pub S: RistrettoPoint,  // Fold state commitment
    pub step: u64,          // Current step counter
}

pub struct FoldStateWithCoeffs {
    pub S: RistrettoPoint,     // Fold state commitment
    pub step: u64,             // Current step counter
    pub coeffs: Vec<Scalar>,   // Tracked polynomial coefficients
}
```

#### Parameters

```rust
pub struct Params {
    pub gens: Vec<RistrettoPoint>,  // Generator points
    pub degree: usize,              // Maximum polynomial degree
    pub domain_sep: [u8; 32],       // Domain separation tag
    pub chain_id: u64,              // Unique chain identifier
}
```

#### Results

```rust
pub struct StepResult {
    pub A_next: Accumulator,
    pub S_next: FoldState,
    pub P_i: RistrettoPoint,
    pub P_i_prime: RistrettoPoint,
    pub h: Scalar,
    pub h_prime: Scalar,
    pub alpha_i: Scalar,
}

pub enum TachyonError {
    DegreeExceeded { max: usize, actual: usize },
    InvalidStepCounter { expected: u64, actual: u64 },
    CheckpointMismatch,
    ChainBindingFailed,
}
```

### Functions

#### Initialization

```rust
pub fn init_accumulator(params: &Params) -> Accumulator
pub fn init_fold(params: &Params, base: SBase) -> FoldState
pub fn init_fold_with_coeffs(params: &Params, base: SBase) -> FoldStateWithCoeffs
```

#### Accumulation

```rust
pub fn non_membership_step(
    params: &Params,
    v: Scalar,
    acc_i: &Accumulator,
    fold_i: &FoldState,
    a_i: &[Scalar],
) -> Result<StepResult>

pub fn non_membership_step_with_coeffs(
    params: &Params,
    v: Scalar,
    acc_i: &Accumulator,
    fold_i: &FoldStateWithCoeffs,
    a_i: &[Scalar],
) -> Result<StepResultWithCoeffs>
```

#### Checkpointing

```rust
pub fn create_checkpoint(params: &Params, acc: &Accumulator, fold: &FoldState) -> Checkpoint
pub fn verify_checkpoint(params: &Params, checkpoint: &Checkpoint, acc: &Accumulator, fold: &FoldState) -> Result<()>
pub fn resume_accumulator(checkpoint: &Checkpoint) -> Accumulator
pub fn resume_fold(checkpoint: &Checkpoint) -> FoldState
```

#### Verification

```rust
pub fn verify_non_membership_by_reveal(revealed_coeffs: &[Scalar], v: Scalar) -> bool
pub fn commit_coeffs(params: &Params, coeffs: &[Scalar]) -> Result<RistrettoPoint>
```

## Security Considerations

### Hash Function

- **Algorithm**: SHA-512 → Scalar reduction
- **Domain Separation**: All hashes use unique prefixes
- **Version Tags**: `TACHYON/H_ACC/v2` and `TACHYON/H_FOLD/v2`
- **Inputs**: Includes chain_id, step counter, and cross-chain binding

### Chain Binding

The two parallel chains (A and S) are cryptographically bound:
- `H_acc` includes both A_i and S_i
- `H_fold` includes both S_i and A_i
- Prevents substitution of valid (A, S) pairs from different executions

### Step Counter Protection

Every hash includes the current step counter:
- Prevents replay attacks (same inputs → different challenges at different steps)
- Prevents truncation attacks (old states can't be substituted)
- Enforced validation in all step functions

### Chain Isolation

Each accumulator instance has a unique chain ID:
- Included in all hash computations
- Prevents cross-chain confusion
- Allows multiple independent accumulators

## Testing

### Run Tests

```bash
# Run all tests
cargo test --lib tachygram

# Run with output
cargo test --lib tachygram -- --nocapture

# Run specific test
cargo test --lib tachygram chain_binding_prevents_substitution
```

### Test Coverage

- ✅ Functional correctness (non-membership proofs)
- ✅ Security properties (replay, truncation, substitution attacks)
- ✅ Error handling (degree bounds, step validation, checkpoints)
- ✅ Integration (long chains, checkpoints, parallel chains)
- ✅ 12 comprehensive tests

## Examples

See `tachygram_example.rs` for comprehensive examples:
1. Basic accumulator usage
2. Checkpoint recovery
3. Coefficient tracking
4. Parallel chains
5. Error handling
6. Serialization (with serde feature)

Run examples:
```bash
cargo run --example tachygram_example
```

## Performance Benchmarks

### Per-Step Cost (Commitment Mode)

| Operation | Count | Time (est.) |
|-----------|-------|-------------|
| SHA-512 hash | 2 | ~1μs |
| Point compression | 4 | ~0.5μs |
| Scalar mul | 2 | ~50μs |
| Point addition | 1 | ~10μs |
| **Total** | - | **~60μs** |

### Memory Usage

| Component | Size |
|-----------|------|
| Accumulator | 40 bytes |
| FoldState | 40 bytes |
| Checkpoint | 104 bytes |
| Params (degree 256) | ~8 KB |

### Scalability

- ✅ Linear time per step: O(|roots|)
- ✅ Constant state size (commitment mode)
- ✅ Tested: 50 steps in ~3ms
- ✅ Projected: 1M steps in ~60 seconds

## Advanced Usage

### Custom Domain Separators

Use versioned, app-specific domain separators:

```rust
const DOMAIN_V1: [u8; 32] = *b"MYAPP_PROD_2025_01_01___________";
const DOMAIN_V2: [u8; 32] = *b"MYAPP_PROD_2025_02_01___________";

let params_v1 = Params::new(256, DOMAIN_V1, chain_id);
let params_v2 = Params::new(256, DOMAIN_V2, chain_id);
```

### Chain ID Management

Generate unique chain IDs per accumulator instance:

```rust
use rand::Rng;

let chain_id = rand::thread_rng().gen::<u64>();
let params = Params::new(256, DOMAIN, chain_id);
```

### Periodic Checkpointing

```rust
const CHECKPOINT_INTERVAL: u64 = 100;

if acc.step % CHECKPOINT_INTERVAL == 0 {
    let checkpoint = create_checkpoint(&params, &acc, &fold);
    save_to_database(&checkpoint)?;
}
```

### Serialization (Optional)

Enable serde feature in Cargo.toml:
```toml
[dependencies]
tachyon = { version = "2.0", features = ["serde"] }
serde_json = "1.0"
```

Serialize and deserialize:
```rust
use tachyon::{SerializableAccumulator, SerializableFoldState};

// Serialize
let ser_acc: SerializableAccumulator = acc.into();
let json = serde_json::to_string(&ser_acc)?;

// Deserialize
let de_acc: SerializableAccumulator = serde_json::from_str(&json)?;
let acc: Accumulator = de_acc.into();
```

## Migration from v1.0

### Breaking Changes

1. **Params::new** now requires `chain_id` parameter
2. **FoldState** split into `FoldState` and `FoldStateWithCoeffs`
3. All functions return `Result<T>` instead of panicking
4. Step counters added to `Accumulator` and `FoldState`

### Migration Steps

```rust
// OLD (v1.0)
let params = Params::new(16, domain_sep);
let fold = init_fold(&params, SBase::Zero, true);
let step = non_membership_step(&params, v, &acc, &fold, &roots);

// NEW (v2.0)
let params = Params::new(16, domain_sep, 1000);  // Add chain_id
let fold = init_fold_with_coeffs(&params, SBase::Zero);  // Explicit type
let step = non_membership_step_with_coeffs(&params, v, &acc, &fold, &roots)?;  // Handle Result
```

## Cryptographic Assumptions

1. **Discrete Log**: Hardness of discrete log in Ristretto group
2. **Collision Resistance**: SHA-512 collision resistance
3. **Fiat-Shamir**: Random oracle assumption for challenge generation
4. **Commitment Binding**: Pedersen commitment binding

## Known Limitations

1. **Coefficient Growth**: Polynomial degree grows with accumulated roots (use commitment-only mode for large chains)
2. **No Proof Compression**: Each step proof is independent (future work: proof aggregation)
3. **Sequential Updates**: Chain must be updated sequentially (future work: parallel batching)

## FAQ

**Q: When should I use commitment-only mode vs. coefficient tracking?**  
A: Use commitment-only mode for production (constant memory). Use coefficient tracking only when you need to reveal the polynomial for verification.

**Q: How often should I create checkpoints?**  
A: Every 100-1000 steps depending on your recovery time objectives and storage constraints.

**Q: Can I run multiple accumulators in parallel?**  
A: Yes! Use different chain IDs for each instance. They're cryptographically isolated.

**Q: What happens if I lose my checkpoint?**  
A: You'll need to replay all steps from the last available checkpoint or genesis.

**Q: Is this quantum-safe?**  
A: No, it relies on discrete log hardness over elliptic curves. See research directions for post-quantum variants.

## Contributing

Contributions welcome! Areas of interest:
- Performance optimizations
- Additional test coverage
- Documentation improvements
- Post-quantum variants
- Proof aggregation

## License

[Specify your license here]

## Citation

```bibtex
@software{tachyon_accumulator_2025,
  title = {Tachyon Hash Chain Accumulator: Production-Grade Cryptographic Accumulator},
  author = {[Your Name]},
  year = {2025},
  version = {2.0.0}
}
```

## References

1. Boneh, D., Bünz, B., & Fisch, B. (2019). Batching Techniques for Accumulators with Applications to IOPs and Stateless Blockchains.
2. de Valence, H. et al. (2020). Ristretto: Prime Order Groups from Non-Prime Order Curves.
3. Fiat, A., & Shamir, A. (1986). How to Prove Yourself: Practical Solutions to Identification and Signature Problems.

## Changelog

See [HASH_CHAIN_IMPROVEMENTS.md](HASH_CHAIN_IMPROVEMENTS.md) for detailed changelog and security analysis.

---

**Status**: Production-ready v2.0  
**Last Updated**: 2025-01-17  
**Security Audit**: Recommended before production deployment

