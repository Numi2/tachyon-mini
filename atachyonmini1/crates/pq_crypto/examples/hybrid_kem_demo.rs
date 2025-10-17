//! Example demonstrating X25519/ML-KEM hybrid KEM for out-of-band payments
//! This example shows how to use the hybrid KEM construction for secure payments

use pq_crypto::{HybridKem, HybridOutOfBandPayment};

fn main() -> anyhow::Result<()> {
    println!("=== Tachyon Hybrid KEM Demo (X25519 + ML-KEM-768) ===\n");

    // Step 1: Generate recipient's hybrid keypair
    println!("1. Generating recipient's hybrid keypair...");
    let (recipient_pk, recipient_sk) = HybridKem::generate_keypair()?;
    println!("   ✓ Generated X25519 + ML-KEM-768 keypair");
    println!("   - X25519 public key size: {} bytes", recipient_pk.x25519_pk.as_bytes().len());
    println!("   - ML-KEM public key size: {} bytes", recipient_pk.mlkem_pk.as_bytes().len());
    println!("   - Total public key size: {} bytes\n", recipient_pk.to_bytes().len());

    // Step 2: Create out-of-band payment
    println!("2. Creating encrypted payment metadata...");
    let payment_metadata = b"payment_to:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh|amount:0.5_BTC|memo:Coffee payment";
    let context = b"tachyon_oob_payment_v1";
    
    let payment = HybridOutOfBandPayment::new(
        recipient_pk.clone(),
        payment_metadata,
        context.to_vec(),
    )?;
    println!("   ✓ Created encrypted payment");
    println!("   - Encrypted metadata size: {} bytes", payment.encrypted_metadata.len());
    println!("   - X25519 ciphertext size: {} bytes", payment.kem_ciphertext.x25519_ct.as_bytes().len());
    println!("   - ML-KEM ciphertext size: {} bytes\n", payment.kem_ciphertext.mlkem_ct.as_bytes().len());

    // Step 3: Verify payment structure
    println!("3. Verifying payment structure...");
    payment.verify()?;
    println!("   ✓ Payment structure is valid\n");

    // Step 4: Serialize payment for transmission
    println!("4. Serializing payment for transmission...");
    let serialized = payment.to_bytes()?;
    println!("   ✓ Serialized payment: {} bytes\n", serialized.len());

    // Step 5: Deserialize payment (simulating network transmission)
    println!("5. Deserializing payment...");
    let deserialized = HybridOutOfBandPayment::from_bytes(&serialized)?;
    println!("   ✓ Payment deserialized successfully\n");

    // Step 6: Decrypt payment with recipient's key
    println!("6. Decrypting payment with recipient's key...");
    let decrypted_metadata = deserialized.decrypt(&recipient_sk)?;
    println!("   ✓ Payment decrypted successfully");
    println!("   - Decrypted: {}\n", String::from_utf8_lossy(&decrypted_metadata));

    // Step 7: Verify correctness
    println!("7. Verifying decryption correctness...");
    assert_eq!(decrypted_metadata, payment_metadata);
    println!("   ✓ Decrypted metadata matches original!\n");

    // Step 8: Demonstrate security properties
    println!("8. Testing security properties...");
    
    // Test with wrong key
    let (_wrong_pk, wrong_sk) = HybridKem::generate_keypair()?;
    let wrong_key_result = deserialized.decrypt(&wrong_sk);
    println!("   ✓ Wrong key decryption fails (as expected): {}", 
             wrong_key_result.is_err());

    // Show key sizes
    println!("\n=== Key Size Summary ===");
    println!("X25519 public key:      32 bytes");
    println!("ML-KEM-768 public key:  1184 bytes");
    println!("Hybrid public key:      1216 bytes");
    println!("\nX25519 ciphertext:      32 bytes");
    println!("ML-KEM-768 ciphertext:  1088 bytes");
    println!("Hybrid ciphertext:      1120 bytes");
    println!("\nShared secret:          32 bytes (BLAKE3-combined)");

    println!("\n=== Security Properties ===");
    println!("✓ Classical security:     X25519 (128-bit)");
    println!("✓ Post-quantum security:  ML-KEM-768 (NIST Level 3)");
    println!("✓ Hybrid security:        Resistant to both classical and quantum attacks");
    println!("✓ Secret combination:     BLAKE3 KDF with domain separation");

    Ok(())
}

