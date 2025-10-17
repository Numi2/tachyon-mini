# Quick Start: Hybrid KEM (X25519 + ML-KEM-768)

## Basic Usage

### 1. Generate Keypair

```rust
use pq_crypto::HybridKem;

let (public_key, secret_key) = HybridKem::generate_keypair()?;
```

### 2. Encapsulate (Sender)

```rust
let (ciphertext, shared_secret) = HybridKem::encapsulate(&public_key)?;
// Use shared_secret to encrypt your data
```

### 3. Decapsulate (Receiver)

```rust
let shared_secret = HybridKem::decapsulate(&secret_key, &ciphertext)?;
// Use shared_secret to decrypt data
```

## Out-of-Band Payments

### Complete Example

```rust
use pq_crypto::{HybridKem, HybridOutOfBandPayment};

// Receiver: Generate keypair
let (recipient_pk, recipient_sk) = HybridKem::generate_keypair()?;

// Sender: Create encrypted payment
let payment_data = b"send 100 BTC to bc1q...";
let payment = HybridOutOfBandPayment::new(
    recipient_pk,
    payment_data,
    b"payment_v1".to_vec(),
)?;

// Serialize for transmission (e.g., over network, QR code)
let serialized = payment.to_bytes()?;

// --- Transfer serialized payment ---

// Receiver: Deserialize and decrypt
let payment = HybridOutOfBandPayment::from_bytes(&serialized)?;
let decrypted = payment.decrypt(&recipient_sk)?;

assert_eq!(decrypted, payment_data);
```

## Running Tests

```bash
# Run all tests
cargo test -p pq_crypto

# Run hybrid-specific tests
cargo test -p pq_crypto test_hybrid

# Run the demo
cargo run -p pq_crypto --example hybrid_kem_demo
```

## Key Sizes

- **Public Key**: 1,216 bytes
- **Secret Key**: 2,432 bytes  
- **Ciphertext**: 1,120 bytes
- **Shared Secret**: 32 bytes

## Security Level

- **Classical**: ~128-bit (X25519)
- **Quantum**: ~128-bit (ML-KEM-768, NIST Level 3)
- **Hybrid**: Resistant to both classical and quantum attacks

## API Reference

See `HYBRID_KEM.md` for detailed documentation.

## Example Output

```
=== Tachyon Hybrid KEM Demo (X25519 + ML-KEM-768) ===

1. Generating recipient's hybrid keypair...
   ✓ Generated X25519 + ML-KEM-768 keypair

2. Creating encrypted payment metadata...
   ✓ Created encrypted payment

6. Decrypting payment with recipient's key...
   ✓ Payment decrypted successfully

=== Security Properties ===
✓ Classical security:     X25519 (128-bit)
✓ Post-quantum security:  ML-KEM-768 (NIST Level 3)
✓ Hybrid security:        Resistant to both classical and quantum attacks
```

## Next Steps

1. Read `HYBRID_KEM.md` for detailed technical documentation
2. Run `cargo run -p pq_crypto --example hybrid_kem_demo` to see it in action
3. Check `examples/hybrid_kem_demo.rs` for integration examples
4. Review `src/lib.rs` for API details

