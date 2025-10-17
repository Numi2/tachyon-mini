//! # pq_crypto
//! Numan Thabit 2025
//! Post-quantum cryptography utilities for Tachyon-mini.
//! Provides KEM (Key Encapsulation Mechanism) and AEAD encryption for out-of-band payments.
//!
//! ## Features
//!
//! - **Hybrid KEM**: X25519/ML-KEM-768 hybrid key encapsulation providing both classical and post-quantum security
//! - **Legacy KEM**: ML-KEM-768 (Kyber768) only for backwards compatibility
//! - **AEAD Encryption**: AES-256-GCM for authenticated encryption
//! - **Digital Signatures**: Dilithium3/ML-DSA-65 for post-quantum signatures
//! - **Nullifier Privacy**: Epoch-tagged VRF-based nullifier blinding
//!
//! ## Hybrid KEM Example
//!
//! ```rust
//! use pq_crypto::{HybridKem, HybridOutOfBandPayment};
//!
//! // Generate recipient's hybrid keypair (X25519 + ML-KEM-768)
//! let (recipient_pk, recipient_sk) = HybridKem::generate_keypair().unwrap();
//!
//! // Sender creates encrypted payment metadata
//! let payment_metadata = b"payment_address:1000 satoshis";
//! let context = b"out_of_band_payment_v1";
//! let payment = HybridOutOfBandPayment::new(
//!     recipient_pk,
//!     payment_metadata,
//!     context.to_vec(),
//! ).unwrap();
//!
//! // Recipient decrypts the payment
//! let decrypted = payment.decrypt(&recipient_sk).unwrap();
//! assert_eq!(decrypted, payment_metadata);
//! ```
//!
//! ## Security Properties
//!
//! The hybrid KEM construction provides:
//! - **Classical security**: 128-bit security via X25519 ECDH
//! - **Post-quantum security**: NIST Level 3 security via ML-KEM-768
//! - **Combined security**: Resistant to both classical and quantum attacks
//! - **Key separation**: Independent key generation for X25519 and ML-KEM
//! - **Secret combination**: BLAKE3-based KDF for combining shared secrets

use anyhow::{anyhow, Result};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;
// Bring Kyber KEM trait methods (as_bytes, from_bytes) into scope
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
// Bring signature trait methods (as_bytes, from_bytes) into scope
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

/// Size of Kyber768 public key in bytes
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1184;

/// Size of Kyber768 secret key in bytes
pub const KYBER_SECRET_KEY_SIZE: usize = 2400;

/// Size of Kyber768 ciphertext in bytes
pub const KYBER_CIPHERTEXT_SIZE: usize = 1088;

/// Size of Kyber768 shared secret in bytes
pub const KYBER_SHARED_SECRET_SIZE: usize = 32;

/// Size of AES-256-GCM key in bytes
pub const AES_KEY_SIZE: usize = 32;

/// Size of AES-256-GCM nonce in bytes
pub const AES_NONCE_SIZE: usize = 12;

/// Size of VRF output for blinding (32 bytes)
pub const VRF_OUTPUT_SIZE: usize = 32;

/// Size of epoch tag for nullifier blinding (8 bytes)
pub const EPOCH_TAG_SIZE: usize = 8;

/// Kyber768 public key wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KyberPublicKey {
    /// Raw public key bytes
    pub bytes: Vec<u8>,
}

impl KyberPublicKey {
    /// Create a new public key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Create a public key from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KYBER_PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "Invalid public key size: expected {}, got {}",
                KYBER_PUBLIC_KEY_SIZE,
                bytes.len()
            ));
        }
        Ok(Self::new(bytes.to_vec()))
    }
}

impl fmt::Display for KyberPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KyberPublicKey({})", hex::encode(&self.bytes[..8]))
    }
}

/// Kyber768 secret key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberSecretKey {
    /// Raw secret key bytes
    pub bytes: Vec<u8>,
}

impl KyberSecretKey {
    /// Create a new secret key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for KyberSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Kyber768 ciphertext wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KyberCiphertext {
    /// Raw ciphertext bytes
    pub bytes: Vec<u8>,
}

impl KyberCiphertext {
    /// Create a new ciphertext from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the ciphertext as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Create a ciphertext from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(anyhow!(
                "Invalid ciphertext size: expected {}, got {}",
                KYBER_CIPHERTEXT_SIZE,
                bytes.len()
            ));
        }
        Ok(Self::new(bytes.to_vec()))
    }
}

/// Epoch tag for nullifier blinding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTag {
    /// Epoch number (8 bytes)
    pub epoch: u64,
}

impl EpochTag {
    /// Create a new epoch tag
    pub fn new(epoch: u64) -> Self {
        Self { epoch }
    }

    /// Get epoch tag as bytes
    pub fn as_bytes(&self) -> [u8; EPOCH_TAG_SIZE] {
        self.epoch.to_le_bytes()
    }

    /// Create epoch tag from bytes
    pub fn from_bytes(bytes: &[u8; EPOCH_TAG_SIZE]) -> Self {
        let epoch = u64::from_le_bytes(*bytes);
        Self::new(epoch)
    }

    /// Get current epoch (simplified - in production would use block height / time)
    pub fn current() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
        // Simple epoch calculation (every 24 hours)
        let epoch = timestamp / (24 * 60 * 60);
        Self::new(epoch)
    }
}

impl Default for EpochTag {
    fn default() -> Self {
        Self::current()
    }
}

/// VRF output for nullifier blinding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput {
    /// VRF output bytes (32 bytes)
    pub output: [u8; VRF_OUTPUT_SIZE],
}

impl VrfOutput {
    /// Create a new VRF output
    pub fn new(output: [u8; VRF_OUTPUT_SIZE]) -> Self {
        Self { output }
    }

    /// Generate a pseudo-random VRF output for demo purposes
    /// In production, this would use a proper VRF like EC-VRF
    pub fn generate_pseudo_random(nullifier_seed: &[u8; 32], epoch: &EpochTag) -> Self {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(b"vrf_blinding");
        hasher.update(nullifier_seed);
        hasher.update(&epoch.as_bytes());

        let hash = hasher.finalize();
        let mut output = [0u8; VRF_OUTPUT_SIZE];
        output.copy_from_slice(hash.as_bytes());

        Self::new(output)
    }

    /// Get VRF output as bytes
    pub fn as_bytes(&self) -> &[u8; VRF_OUTPUT_SIZE] {
        &self.output
    }
}

/// Privacy-preserving nullifier with blinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedNullifier {
    /// Original nullifier hash
    pub nullifier: [u8; 32],
    /// Epoch tag for this nullifier
    pub epoch_tag: EpochTag,
    /// VRF output for blinding
    pub vrf_output: VrfOutput,
    /// Blinded nullifier (nullifier XOR vrf_output)
    pub blinded_value: [u8; 32],
}

impl BlindedNullifier {
    /// Create a new blinded nullifier
    pub fn new(nullifier: [u8; 32], epoch_tag: EpochTag, vrf_output: VrfOutput) -> Self {
        let mut blinded_value = [0u8; 32];

        // Simple XOR blinding (in production would use proper cryptographic blinding)
        for i in 0..32 {
            blinded_value[i] = nullifier[i] ^ vrf_output.output[i];
        }

        Self {
            nullifier,
            epoch_tag,
            vrf_output,
            blinded_value,
        }
    }

    /// Create a blinded nullifier with current epoch and random VRF
    pub fn new_blinded(nullifier: [u8; 32]) -> Self {
        let epoch_tag = EpochTag::current();
        let vrf_output = VrfOutput::generate_pseudo_random(&nullifier, &epoch_tag);
        Self::new(nullifier, epoch_tag, vrf_output)
    }

    /// Verify that this blinded nullifier corresponds to the given nullifier
    pub fn verify(&self, candidate_nullifier: &[u8; 32]) -> bool {
        // Check epoch is current or recent (within 1 epoch)
        let current_epoch = EpochTag::current();
        let epoch_diff = current_epoch.epoch.abs_diff(self.epoch_tag.epoch);

        if epoch_diff > 1 {
            return false;
        }

        // Recompute VRF and verify blinding
        let recomputed_vrf =
            VrfOutput::generate_pseudo_random(candidate_nullifier, &self.epoch_tag);
        let mut recomputed_blinded = [0u8; 32];

        for i in 0..32 {
            recomputed_blinded[i] = candidate_nullifier[i] ^ recomputed_vrf.output[i];
        }

        recomputed_blinded == self.blinded_value
    }

    /// Get the blinded nullifier value for storage/transmission
    pub fn blinded_value(&self) -> &[u8; 32] {
        &self.blinded_value
    }

    /// Get the epoch tag
    pub fn epoch_tag(&self) -> &EpochTag {
        &self.epoch_tag
    }
}

/// Nullifier derivation strategy (backwards-compatible toggle)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NullifierDerivationMode {
    /// Legacy derivation (direct hash of commitment)
    Legacy,
    /// Blinded derivation using epoch-tagged VRF
    Blinded,
}

/// Derive a nullifier from a note commitment and rseed under a chosen mode
pub fn derive_nullifier(
    note_commitment: &[u8; 32],
    rseed: &[u8; 32],
    mode: NullifierDerivationMode,
) -> [u8; 32] {
    match mode {
        NullifierDerivationMode::Legacy => {
            // Hash(note_commitment || rseed)
            let mut h = blake3::Hasher::new();
            h.update(b"nullifier:legacy:v1");
            h.update(note_commitment);
            h.update(rseed);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.finalize().as_bytes());
            out
        }
        NullifierDerivationMode::Blinded => {
            // Compute base nullifier, then blind with epoch-tagged VRF
            let mut h = blake3::Hasher::new();
            h.update(b"nullifier:base:v1");
            h.update(note_commitment);
            h.update(rseed);
            let base = h.finalize();
            let mut base_arr = [0u8; 32];
            base_arr.copy_from_slice(base.as_bytes());

            let blinded = BlindedNullifier::new_blinded(base_arr);
            *blinded.blinded_value()
        }
    }
}

// =============================
// NF2 (Spend-authority-only) nullifier derivation
// =============================

/// Derive spend-nullifier key snk = PRF_snk(sk, "snk")
pub fn derive_spend_nullifier_key(spend_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"prf_snk:v1");
    h.update(spend_secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// PRF_t(snk, rho) used as a trapdoor for the revealed nullifier
pub fn derive_trapdoor_t(snk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"prf_t:v1");
    h.update(snk);
    h.update(rho);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// NF2 = H("orchard2.nf" || cm || rho || t) where t = PRF_t(snk, rho)
pub fn derive_nf2(
    note_commitment: &[u8; 32],
    rho: &[u8; 32],
    spend_nullifier_key: &[u8; 32],
) -> [u8; 32] {
    let t = derive_trapdoor_t(spend_nullifier_key, rho);
    let mut h = blake3::Hasher::new();
    h.update(b"orchard2.nf:v1");
    h.update(note_commitment);
    h.update(rho);
    h.update(&t);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// =============================
// Tachyon note and nullifier helpers (prototype)
// =============================

/// Derive a per-payment commitment key from a shared secret established out-of-band.
/// This binds the note commitment to the shared secret while remaining unlinkable.
pub fn derive_commitment_key(shared_secret: &[u8; KYBER_SHARED_SECRET_SIZE]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"tachyon:cmk:v1");
    h.update(shared_secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Derive a per-note nonce from the shared secret, payment key, and value.
/// Including value ensures domain separation across values for the same payment key.
pub fn derive_note_nonce(
    shared_secret: &[u8; KYBER_SHARED_SECRET_SIZE],
    payment_key: &[u8; 32],
    value: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"tachyon:note:nonce:v1");
    h.update(shared_secret);
    h.update(payment_key);
    h.update(&value.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Compute a note commitment from core note fields.
/// commitment = H(tag || payment_key || value || nonce || commitment_key)
pub fn compute_note_commitment(
    payment_key: &[u8; 32],
    value: u64,
    nonce: &[u8; 32],
    commitment_key: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"tachyon:note:cm:v1");
    h.update(payment_key);
    h.update(&value.to_le_bytes());
    h.update(nonce);
    h.update(commitment_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Flavored nullifier derivation used by Tachyon prototype.
/// NF = H(tag || cm || rho || PRF_t(snk, rho) || flavor)
pub fn derive_tachyon_nullifier_flavored(
    note_commitment: &[u8; 32],
    rho: &[u8; 32],
    spend_nullifier_key: &[u8; 32],
    flavor: u8,
) -> [u8; 32] {
    let t = derive_trapdoor_t(spend_nullifier_key, rho);
    let mut h = blake3::Hasher::new();
    h.update(b"tachyon.nf:v1");
    h.update(note_commitment);
    h.update(rho);
    h.update(&t);
    h.update(&[flavor]);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Token for rate limiting and unlinkability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// Token ID (unique identifier)
    pub token_id: [u8; 16],
    /// Token expiration time
    pub expires_at: u64,
    /// Token usage counter
    pub usage_count: u32,
    /// Maximum allowed uses
    pub max_uses: u32,
    /// Rate limiting window start
    pub rate_window_start: u64,
    /// Request count in current window
    pub request_count: u32,
    /// Maximum requests per window
    pub max_requests_per_window: u32,
}

impl AccessToken {
    /// Create a new access token
    pub fn new(max_uses: u32, max_requests_per_window: u32, lifetime_seconds: u64) -> Self {
        let mut token_id = [0u8; 16];
        OsRng.fill_bytes(&mut token_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        Self {
            token_id,
            expires_at: now + lifetime_seconds,
            usage_count: 0,
            max_uses,
            rate_window_start: now,
            request_count: 0,
            max_requests_per_window,
        }
    }

    /// Check if token is still valid
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        now < self.expires_at && self.usage_count < self.max_uses
    }

    /// Check if request is allowed (rate limiting)
    pub fn can_make_request(&self) -> bool {
        if !self.is_valid() {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        // Reset rate window if needed (24 hour windows)
        if now - self.rate_window_start > 24 * 60 * 60 {
            return true;
        }

        self.request_count < self.max_requests_per_window
    }

    /// Record a request
    pub fn record_request(&mut self) {
        self.usage_count += 1;
        self.request_count += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        // Reset rate window if needed
        if now - self.rate_window_start > 24 * 60 * 60 {
            self.rate_window_start = now;
            self.request_count = 1;
        }
    }

    /// Get token ID as bytes
    pub fn token_id(&self) -> &[u8; 16] {
        &self.token_id
    }
}

/// Request padding for unlinkability
#[derive(Debug, Clone)]
pub struct PaddedRequest {
    /// Actual request data
    pub request_data: Vec<u8>,
    /// Padding data (random bytes)
    pub padding: Vec<u8>,
    /// Total request size (including padding)
    pub total_size: usize,
}

impl PaddedRequest {
    /// Create a new padded request
    pub fn new(request_data: Vec<u8>, target_size: usize) -> Self {
        let mut padding = Vec::new();
        let padding_size = target_size.saturating_sub(request_data.len());

        if padding_size > 0 {
            padding = vec![0u8; padding_size];
            OsRng.fill_bytes(&mut padding);
        }

        Self {
            request_data,
            padding,
            total_size: target_size,
        }
    }

    /// Get the full padded request data
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.request_data.clone();
        data.extend_from_slice(&self.padding);
        data
    }

    /// Extract the original request data (removes padding)
    pub fn extract_request(&self) -> Vec<u8> {
        self.request_data.clone()
    }

    /// Check if this is a dummy request (all padding)
    pub fn is_dummy(&self) -> bool {
        self.request_data.is_empty()
    }
}

impl fmt::Display for KyberCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KyberCiphertext({})", hex::encode(&self.bytes[..8]))
    }
}

/// Simple KEM trait for crypto-agility without breaking existing APIs
pub trait Kem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, [u8; KYBER_SHARED_SECRET_SIZE])>;
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<[u8; KYBER_SHARED_SECRET_SIZE]>;
}

/// Kyber768 KEM wrapper providing keygen/encap/decap using pqcrypto-kyber
pub struct SimpleKem;

impl SimpleKem {
    /// Generate a keypair using Kyber768
    pub fn generate_keypair() -> Result<(KyberPublicKey, KyberSecretKey)> {
        use pqcrypto_kyber::kyber768;
        let (pk, sk) = kyber768::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let sk_bytes = sk.as_bytes().to_vec();
        if pk_bytes.len() != KYBER_PUBLIC_KEY_SIZE || sk_bytes.len() != KYBER_SECRET_KEY_SIZE {
            return Err(anyhow!("Unexpected Kyber key sizes"));
        }
        Ok((KyberPublicKey::new(pk_bytes), KyberSecretKey::new(sk_bytes)))
    }

    /// Encapsulate to a Kyber768 public key
    pub fn encapsulate(
        pk: &KyberPublicKey,
    ) -> Result<(KyberCiphertext, [u8; KYBER_SHARED_SECRET_SIZE])> {
        use pqcrypto_kyber::kyber768;
        let pk_typed = kyber768::PublicKey::from_bytes(pk.as_bytes())
            .map_err(|_| anyhow!("Invalid Kyber public key bytes"))?;
        let (ss, ct) = kyber768::encapsulate(&pk_typed);
        let mut shared_secret = [0u8; KYBER_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&ss.as_bytes()[..KYBER_SHARED_SECRET_SIZE]);
        Ok((KyberCiphertext::new(ct.as_bytes().to_vec()), shared_secret))
    }

    /// Decapsulate using Kyber768 secret key
    pub fn decapsulate(
        sk: &KyberSecretKey,
        ct: &KyberCiphertext,
    ) -> Result<[u8; KYBER_SHARED_SECRET_SIZE]> {
        use pqcrypto_kyber::kyber768;
        let sk_typed = kyber768::SecretKey::from_bytes(sk.as_bytes())
            .map_err(|_| anyhow!("Invalid Kyber secret key bytes"))?;
        let ct_typed = kyber768::Ciphertext::from_bytes(ct.as_bytes())
            .map_err(|_| anyhow!("Invalid Kyber ciphertext bytes"))?;
        let ss = kyber768::decapsulate(&ct_typed, &sk_typed);
        let mut shared_secret = [0u8; KYBER_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&ss.as_bytes()[..KYBER_SHARED_SECRET_SIZE]);
        Ok(shared_secret)
    }
}

impl Kem for SimpleKem {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = KyberCiphertext;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey)> {
        SimpleKem::generate_keypair()
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, [u8; KYBER_SHARED_SECRET_SIZE])> {
        SimpleKem::encapsulate(pk)
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<[u8; KYBER_SHARED_SECRET_SIZE]> {
        SimpleKem::decapsulate(sk, ct)
    }
}

// =============================
// X25519 KEM for hybrid construction
// =============================

/// Size of X25519 public key in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 secret key in bytes
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// Size of X25519 shared secret in bytes
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// Size of X25519 ciphertext (ephemeral public key) in bytes
pub const X25519_CIPHERTEXT_SIZE: usize = 32;

/// X25519 public key wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519PublicKey {
    /// Raw public key bytes
    pub bytes: [u8; X25519_PUBLIC_KEY_SIZE],
}

impl X25519PublicKey {
    /// Create a new public key from bytes
    pub fn new(bytes: [u8; X25519_PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Create a public key from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "Invalid X25519 public key size: expected {}, got {}",
                X25519_PUBLIC_KEY_SIZE,
                bytes.len()
            ));
        }
        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }
}

impl fmt::Display for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519PublicKey({})", hex::encode(&self.bytes[..8]))
    }
}

/// X25519 secret key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519SecretKey {
    /// Raw secret key bytes
    pub bytes: [u8; X25519_SECRET_KEY_SIZE],
}

impl X25519SecretKey {
    /// Create a new secret key from bytes
    pub fn new(bytes: [u8; X25519_SECRET_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8; X25519_SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Create a secret key from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_SECRET_KEY_SIZE {
            return Err(anyhow!(
                "Invalid X25519 secret key size: expected {}, got {}",
                X25519_SECRET_KEY_SIZE,
                bytes.len()
            ));
        }
        let mut arr = [0u8; X25519_SECRET_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }
}

impl Drop for X25519SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// X25519 ciphertext (ephemeral public key)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519Ciphertext {
    /// Ephemeral public key bytes
    pub bytes: [u8; X25519_CIPHERTEXT_SIZE],
}

impl X25519Ciphertext {
    /// Create a new ciphertext from bytes
    pub fn new(bytes: [u8; X25519_CIPHERTEXT_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get the ciphertext as bytes
    pub fn as_bytes(&self) -> &[u8; X25519_CIPHERTEXT_SIZE] {
        &self.bytes
    }

    /// Create a ciphertext from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_CIPHERTEXT_SIZE {
            return Err(anyhow!(
                "Invalid X25519 ciphertext size: expected {}, got {}",
                X25519_CIPHERTEXT_SIZE,
                bytes.len()
            ));
        }
        let mut arr = [0u8; X25519_CIPHERTEXT_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }
}

impl fmt::Display for X25519Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Ciphertext({})", hex::encode(&self.bytes[..8]))
    }
}

/// X25519 KEM implementation
pub struct X25519Kem;

impl X25519Kem {
    /// Generate an X25519 keypair
    pub fn generate_keypair() -> Result<(X25519PublicKey, X25519SecretKey)> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Ok((
            X25519PublicKey::new(public.to_bytes()),
            X25519SecretKey::new(secret.to_bytes()),
        ))
    }

    /// Encapsulate to an X25519 public key
    /// Returns (ephemeral_public_key, shared_secret)
    pub fn encapsulate(
        pk: &X25519PublicKey,
    ) -> Result<(X25519Ciphertext, [u8; X25519_SHARED_SECRET_SIZE])> {
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate ephemeral keypair
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Compute shared secret with recipient's public key
        let recipient_pk = PublicKey::from(*pk.as_bytes());
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

        Ok((
            X25519Ciphertext::new(ephemeral_public.to_bytes()),
            shared_secret.to_bytes(),
        ))
    }

    /// Decapsulate using X25519 secret key and ephemeral public key
    pub fn decapsulate(
        sk: &X25519SecretKey,
        ct: &X25519Ciphertext,
    ) -> Result<[u8; X25519_SHARED_SECRET_SIZE]> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(*sk.as_bytes());
        let ephemeral_public = PublicKey::from(*ct.as_bytes());

        let shared_secret = secret.diffie_hellman(&ephemeral_public);
        Ok(shared_secret.to_bytes())
    }
}

// =============================
// Hybrid X25519/ML-KEM KEM
// =============================

/// Hybrid public key containing both X25519 and ML-KEM public keys
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// X25519 public key
    pub x25519_pk: X25519PublicKey,
    /// ML-KEM (Kyber768) public key
    pub mlkem_pk: KyberPublicKey,
}

impl HybridPublicKey {
    /// Create a new hybrid public key
    pub fn new(x25519_pk: X25519PublicKey, mlkem_pk: KyberPublicKey) -> Self {
        Self { x25519_pk, mlkem_pk }
    }

    /// Serialize to bytes (X25519 || ML-KEM)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(X25519_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE);
        bytes.extend_from_slice(self.x25519_pk.as_bytes());
        bytes.extend_from_slice(self.mlkem_pk.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "Invalid hybrid public key size: expected {}, got {}",
                X25519_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE,
                bytes.len()
            ));
        }

        let x25519_pk = X25519PublicKey::from_bytes(&bytes[..X25519_PUBLIC_KEY_SIZE])?;
        let mlkem_pk = KyberPublicKey::from_bytes(&bytes[X25519_PUBLIC_KEY_SIZE..])?;

        Ok(Self::new(x25519_pk, mlkem_pk))
    }
}

impl fmt::Display for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridPublicKey(x25519={}, mlkem={})", 
               hex::encode(&self.x25519_pk.bytes[..4]),
               hex::encode(&self.mlkem_pk.bytes[..4]))
    }
}

/// Hybrid secret key containing both X25519 and ML-KEM secret keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSecretKey {
    /// X25519 secret key
    pub x25519_sk: X25519SecretKey,
    /// ML-KEM (Kyber768) secret key
    pub mlkem_sk: KyberSecretKey,
}

impl HybridSecretKey {
    /// Create a new hybrid secret key
    pub fn new(x25519_sk: X25519SecretKey, mlkem_sk: KyberSecretKey) -> Self {
        Self { x25519_sk, mlkem_sk }
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        // Individual keys already implement Drop with zeroization
    }
}

/// Hybrid ciphertext containing both X25519 and ML-KEM ciphertexts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// X25519 ciphertext (ephemeral public key)
    pub x25519_ct: X25519Ciphertext,
    /// ML-KEM (Kyber768) ciphertext
    pub mlkem_ct: KyberCiphertext,
}

impl HybridCiphertext {
    /// Create a new hybrid ciphertext
    pub fn new(x25519_ct: X25519Ciphertext, mlkem_ct: KyberCiphertext) -> Self {
        Self { x25519_ct, mlkem_ct }
    }

    /// Serialize to bytes (X25519 || ML-KEM)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(X25519_CIPHERTEXT_SIZE + KYBER_CIPHERTEXT_SIZE);
        bytes.extend_from_slice(self.x25519_ct.as_bytes());
        bytes.extend_from_slice(self.mlkem_ct.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_CIPHERTEXT_SIZE + KYBER_CIPHERTEXT_SIZE {
            return Err(anyhow!(
                "Invalid hybrid ciphertext size: expected {}, got {}",
                X25519_CIPHERTEXT_SIZE + KYBER_CIPHERTEXT_SIZE,
                bytes.len()
            ));
        }

        let x25519_ct = X25519Ciphertext::from_bytes(&bytes[..X25519_CIPHERTEXT_SIZE])?;
        let mlkem_ct = KyberCiphertext::from_bytes(&bytes[X25519_CIPHERTEXT_SIZE..])?;

        Ok(Self::new(x25519_ct, mlkem_ct))
    }
}

impl fmt::Display for HybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridCiphertext(x25519={}, mlkem={})", 
               hex::encode(&self.x25519_ct.bytes[..4]),
               hex::encode(&self.mlkem_ct.bytes[..4]))
    }
}

/// Hybrid KEM combining X25519 and ML-KEM (Kyber768)
/// Provides both classical ECDH and post-quantum security
pub struct HybridKem;

impl HybridKem {
    /// Generate a hybrid keypair
    pub fn generate_keypair() -> Result<(HybridPublicKey, HybridSecretKey)> {
        let (x25519_pk, x25519_sk) = X25519Kem::generate_keypair()?;
        let (mlkem_pk, mlkem_sk) = SimpleKem::generate_keypair()?;

        Ok((
            HybridPublicKey::new(x25519_pk, mlkem_pk),
            HybridSecretKey::new(x25519_sk, mlkem_sk),
        ))
    }

    /// Encapsulate to a hybrid public key
    /// Returns (hybrid_ciphertext, combined_shared_secret)
    /// The shared secret is derived by combining both X25519 and ML-KEM shared secrets using BLAKE3
    pub fn encapsulate(
        pk: &HybridPublicKey,
    ) -> Result<(HybridCiphertext, [u8; 32])> {
        // Encapsulate to X25519 public key
        let (x25519_ct, x25519_ss) = X25519Kem::encapsulate(&pk.x25519_pk)?;

        // Encapsulate to ML-KEM public key
        let (mlkem_ct, mlkem_ss) = SimpleKem::encapsulate(&pk.mlkem_pk)?;

        // Combine both shared secrets using BLAKE3 KDF
        let combined_ss = Self::combine_shared_secrets(&x25519_ss, &mlkem_ss);

        Ok((
            HybridCiphertext::new(x25519_ct, mlkem_ct),
            combined_ss,
        ))
    }

    /// Decapsulate using hybrid secret key
    /// Returns the combined shared secret derived from both X25519 and ML-KEM
    pub fn decapsulate(
        sk: &HybridSecretKey,
        ct: &HybridCiphertext,
    ) -> Result<[u8; 32]> {
        // Decapsulate X25519 ciphertext
        let x25519_ss = X25519Kem::decapsulate(&sk.x25519_sk, &ct.x25519_ct)?;

        // Decapsulate ML-KEM ciphertext
        let mlkem_ss = SimpleKem::decapsulate(&sk.mlkem_sk, &ct.mlkem_ct)?;

        // Combine both shared secrets using the same KDF
        Ok(Self::combine_shared_secrets(&x25519_ss, &mlkem_ss))
    }

    /// Combine X25519 and ML-KEM shared secrets using BLAKE3 KDF
    /// This follows the NIST recommendation for hybrid KEM construction
    fn combine_shared_secrets(
        x25519_ss: &[u8; X25519_SHARED_SECRET_SIZE],
        mlkem_ss: &[u8; KYBER_SHARED_SECRET_SIZE],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tachyon:hybrid_kem:v1");
        hasher.update(x25519_ss);
        hasher.update(mlkem_ss);
        
        let mut combined = [0u8; 32];
        combined.copy_from_slice(hasher.finalize().as_bytes());
        combined
    }
}

impl Kem for HybridKem {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type Ciphertext = HybridCiphertext;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey)> {
        HybridKem::generate_keypair()
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, [u8; KYBER_SHARED_SECRET_SIZE])> {
        HybridKem::encapsulate(pk)
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<[u8; KYBER_SHARED_SECRET_SIZE]> {
        HybridKem::decapsulate(sk, ct)
    }
}

/// Simple AEAD implementation using AES-GCM
pub struct SimpleAead;

impl SimpleAead {
    /// Encrypt
    pub fn encrypt(
        key: &[u8; AES_KEY_SIZE],
        nonce: &[u8; AES_NONCE_SIZE],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce_obj = Nonce::from_slice(nonce);

        let mut ciphertext = cipher
            .encrypt(
                nonce_obj,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce);
        result.append(&mut ciphertext);

        Ok(result)
    }

    /// Decrypt
    pub fn decrypt(
        key: &[u8; AES_KEY_SIZE],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key};

        if ciphertext.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        let nonce = &ciphertext[..AES_NONCE_SIZE];
        let encrypted_data = &ciphertext[AES_NONCE_SIZE..];

        let plaintext = cipher
            .decrypt(
                nonce.into(),
                aes_gcm::aead::Payload {
                    msg: encrypted_data,
                    aad: associated_data,
                },
            )
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        Ok(plaintext)
    }

    /// Generate nonce
    pub fn generate_nonce() -> [u8; AES_NONCE_SIZE] {
        let mut nonce = [0u8; AES_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

/// Out-of-band payment data structure (legacy, ML-KEM only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutOfBandPayment {
    /// Recipient's Kyber public key
    pub recipient_pk: KyberPublicKey,
    /// Kyber ciphertext produced during encapsulation
    pub kem_ciphertext: KyberCiphertext,
    /// Encrypted note metadata
    pub encrypted_metadata: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Associated data for AEAD
    pub associated_data: Vec<u8>,
}

impl OutOfBandPayment {
    /// Create a new out-of-band payment
    pub fn new(
        recipient_pk: KyberPublicKey,
        note_metadata: &[u8],
        associated_data: Vec<u8>,
    ) -> Result<Self> {
        let (kem_ciphertext, mut shared_secret) = SimpleKem::encapsulate(&recipient_pk)?;
        let nonce = SimpleAead::generate_nonce();

        let encrypted_metadata =
            SimpleAead::encrypt(&shared_secret, &nonce, note_metadata, &associated_data)?;
        shared_secret.zeroize();

        Ok(Self {
            recipient_pk,
            kem_ciphertext,
            encrypted_metadata,
            nonce,
            associated_data,
        })
    }

    /// Decrypt the out-of-band payment using recipient's secret key
    pub fn decrypt(&self, recipient_sk: &KyberSecretKey) -> Result<Vec<u8>> {
        let mut shared_secret = SimpleKem::decapsulate(recipient_sk, &self.kem_ciphertext)?;

        let result = SimpleAead::decrypt(
            &shared_secret,
            &self.encrypted_metadata,
            &self.associated_data,
        );
        shared_secret.zeroize();
        result
    }

    /// Verify the payment structure is well-formed
    pub fn verify(&self) -> Result<()> {
        if self.kem_ciphertext.as_bytes().len() != KYBER_CIPHERTEXT_SIZE {
            return Err(anyhow!("Invalid Kyber ciphertext length"));
        }
        if self.encrypted_metadata.is_empty() {
            return Err(anyhow!("Encrypted metadata too short"));
        }
        if self.nonce.len() != AES_NONCE_SIZE {
            return Err(anyhow!("Invalid nonce length"));
        }
        Ok(())
    }
}

/// Hybrid out-of-band payment using X25519/ML-KEM hybrid KEM
/// This provides both classical and post-quantum security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridOutOfBandPayment {
    /// Recipient's hybrid public key
    pub recipient_pk: HybridPublicKey,
    /// Hybrid KEM ciphertext
    pub kem_ciphertext: HybridCiphertext,
    /// Encrypted note metadata
    pub encrypted_metadata: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Associated data for AEAD
    pub associated_data: Vec<u8>,
}

impl HybridOutOfBandPayment {
    /// Create a new hybrid out-of-band payment
    pub fn new(
        recipient_pk: HybridPublicKey,
        note_metadata: &[u8],
        associated_data: Vec<u8>,
    ) -> Result<Self> {
        // Encapsulate using hybrid KEM
        let (kem_ciphertext, mut shared_secret) = HybridKem::encapsulate(&recipient_pk)?;
        let nonce = SimpleAead::generate_nonce();

        // Encrypt metadata using the combined shared secret
        let encrypted_metadata =
            SimpleAead::encrypt(&shared_secret, &nonce, note_metadata, &associated_data)?;
        shared_secret.zeroize();

        Ok(Self {
            recipient_pk,
            kem_ciphertext,
            encrypted_metadata,
            nonce,
            associated_data,
        })
    }

    /// Decrypt the out-of-band payment using recipient's hybrid secret key
    pub fn decrypt(&self, recipient_sk: &HybridSecretKey) -> Result<Vec<u8>> {
        // Decapsulate using hybrid KEM
        let mut shared_secret = HybridKem::decapsulate(recipient_sk, &self.kem_ciphertext)?;

        let result = SimpleAead::decrypt(
            &shared_secret,
            &self.encrypted_metadata,
            &self.associated_data,
        );
        shared_secret.zeroize();
        result
    }

    /// Verify the payment structure is well-formed
    pub fn verify(&self) -> Result<()> {
        // Verify X25519 component
        if self.kem_ciphertext.x25519_ct.as_bytes().len() != X25519_CIPHERTEXT_SIZE {
            return Err(anyhow!("Invalid X25519 ciphertext length"));
        }
        
        // Verify ML-KEM component
        if self.kem_ciphertext.mlkem_ct.as_bytes().len() != KYBER_CIPHERTEXT_SIZE {
            return Err(anyhow!("Invalid ML-KEM ciphertext length"));
        }
        
        // Verify encrypted metadata
        if self.encrypted_metadata.is_empty() {
            return Err(anyhow!("Encrypted metadata too short"));
        }
        
        // Verify nonce
        if self.nonce.len() != AES_NONCE_SIZE {
            return Err(anyhow!("Invalid nonce length"));
        }
        
        Ok(())
    }

    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Serialization failed: {}", e))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("Deserialization failed: {}", e))
    }
}

impl fmt::Display for HybridOutOfBandPayment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridOutOfBandPayment(recipient={}, ct={}, metadata_len={})",
            self.recipient_pk,
            self.kem_ciphertext,
            self.encrypted_metadata.len()
        )
    }
}

/// Generate a random AES key
pub fn generate_aes_key() -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

// =============================
// Suite B (Dilithium3 + BLAKE3)
// =============================

/// Domain separator for Suite B checkpoint signing
pub const SUITE_B_DOMAIN_CHECKPOINT: &[u8] = b"tachyon:suiteb:checkpoint:v1";

/// Dilithium3 public key wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteBPublicKey {
    /// Raw public key bytes
    pub bytes: Vec<u8>,
}

impl SuiteBPublicKey {
    /// Create a new public key from bytes
    pub fn new(bytes: Vec<u8>) -> Self { Self { bytes } }

    /// Access bytes
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }

    /// Construct from bytes (validated on first use)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { Ok(Self::new(bytes.to_vec())) }
}

impl fmt::Display for SuiteBPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SuiteBPublicKey({})", hex::encode(&self.bytes[..std::cmp::min(8, self.bytes.len())]))
    }
}

/// Dilithium3 secret key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteBSecretKey {
    /// Raw secret key bytes
    pub bytes: Vec<u8>,
}

impl SuiteBSecretKey {
    /// Create a new secret key from bytes
    pub fn new(bytes: Vec<u8>) -> Self { Self { bytes } }

    /// Access bytes
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }

    /// Construct from bytes (validated on first use)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { Ok(Self::new(bytes.to_vec())) }
}

impl Drop for SuiteBSecretKey {
    fn drop(&mut self) { self.bytes.zeroize(); }
}

/// Dilithium3 detached signature wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteBSignature {
    /// Raw signature bytes
    pub bytes: Vec<u8>,
}

impl SuiteBSignature {
    /// Create a new signature from bytes
    pub fn new(bytes: Vec<u8>) -> Self { Self { bytes } }

    /// Access bytes
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }

    /// Construct from bytes (validated on first use)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { Ok(Self::new(bytes.to_vec())) }
}

/// Suite B signing API (Dilithium3 + BLAKE3 prehash)
pub struct SuiteB;

impl SuiteB {
    /// Generate a Dilithium3 keypair
    pub fn generate_keypair() -> Result<(SuiteBPublicKey, SuiteBSecretKey)> {
        #[cfg(feature = "mldsa")]
        {
            // ML-DSA65 ~ Dilithium3 level
            use pqcrypto_mldsa::mldsa65;
            let (pk, sk) = mldsa65::keypair();
            Ok((SuiteBPublicKey::new(pk.as_bytes().to_vec()), SuiteBSecretKey::new(sk.as_bytes().to_vec())))
        }
        #[cfg(not(feature = "mldsa"))]
        {
            use pqcrypto_dilithium::dilithium3;
            let (pk, sk) = dilithium3::keypair();
            Ok((SuiteBPublicKey::new(pk.as_bytes().to_vec()), SuiteBSecretKey::new(sk.as_bytes().to_vec())))
        }
    }

    /// Sign a prehashed 32-byte digest
    pub fn sign_prehash(secret_key: &SuiteBSecretKey, digest32: &[u8; 32]) -> Result<SuiteBSignature> {
        #[cfg(feature = "mldsa")]
        {
            use pqcrypto_mldsa::mldsa65;
            let sk = mldsa65::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| anyhow!("Invalid Suite B secret key bytes"))?;
            let sig = mldsa65::detached_sign(digest32, &sk);
            Ok(SuiteBSignature::new(sig.as_bytes().to_vec()))
        }
        #[cfg(not(feature = "mldsa"))]
        {
            use pqcrypto_dilithium::dilithium3;
            let sk = dilithium3::SecretKey::from_bytes(secret_key.as_bytes())
                .map_err(|_| anyhow!("Invalid Suite B secret key bytes"))?;
            let sig = dilithium3::detached_sign(digest32, &sk);
            Ok(SuiteBSignature::new(sig.as_bytes().to_vec()))
        }
    }

    /// Verify a signature over a prehashed 32-byte digest
    pub fn verify_prehash(public_key: &SuiteBPublicKey, digest32: &[u8; 32], signature: &SuiteBSignature) -> bool {
        #[cfg(feature = "mldsa")]
        {
            use pqcrypto_mldsa::mldsa65;
            let pk = match mldsa65::PublicKey::from_bytes(public_key.as_bytes()) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = match mldsa65::DetachedSignature::from_bytes(signature.as_bytes()) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            mldsa65::verify_detached_signature(&sig, digest32, &pk).is_ok()
        }
        #[cfg(not(feature = "mldsa"))]
        {
            use pqcrypto_dilithium::dilithium3;
            let pk = match dilithium3::PublicKey::from_bytes(public_key.as_bytes()) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = match dilithium3::DetachedSignature::from_bytes(signature.as_bytes()) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            dilithium3::verify_detached_signature(&sig, digest32, &pk).is_ok()
        }
    }

    /// Compute a BLAKE3 digest from parts with a domain tag
    pub fn blake3_prehash_with_domain(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        for p in parts { hasher.update(p); }
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_kem() {
        let (pk, sk) = SimpleKem::generate_keypair().unwrap();
        assert_eq!(pk.as_bytes().len(), KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), KYBER_SECRET_KEY_SIZE);

        let (ct, shared_secret) = SimpleKem::encapsulate(&pk).unwrap();
        assert_eq!(ct.as_bytes().len(), KYBER_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret.len(), KYBER_SHARED_SECRET_SIZE);

        let decapsulated_secret = SimpleKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(shared_secret, decapsulated_secret);
    }

    #[test]
    fn test_simple_aead() {
        let key = generate_aes_key();
        let nonce = SimpleAead::generate_nonce();
        let plaintext = b"Hello, world!";
        let associated_data = b"test";

        let ciphertext = SimpleAead::encrypt(&key, &nonce, plaintext, associated_data).unwrap();
        assert!(!ciphertext.is_empty());

        let decrypted = SimpleAead::decrypt(&key, &ciphertext, associated_data).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_oob_payment() {
        let (recipient_pk, recipient_sk) = SimpleKem::generate_keypair().unwrap();
        let note_metadata = b"test note metadata";
        let associated_data = b"payment_context";

        let payment = OutOfBandPayment::new(
            recipient_pk.clone(),
            note_metadata,
            associated_data.to_vec(),
        )
        .unwrap();
        payment.verify().unwrap();

        let decrypted_metadata = payment.decrypt(&recipient_sk).unwrap();
        assert_eq!(note_metadata.to_vec(), decrypted_metadata);
    }

    #[test]
    fn test_suite_b_sign_verify() {
        let (pk, sk) = SuiteB::generate_keypair().unwrap();
        let digest = SuiteB::blake3_prehash_with_domain(b"test_suiteb", &[b"hello", b"world"]);
        let sig = SuiteB::sign_prehash(&sk, &digest).unwrap();
        assert!(SuiteB::verify_prehash(&pk, &digest, &sig));

        // Negative test
        let mut digest_bad = digest;
        digest_bad[0] ^= 0x01;
        assert!(!SuiteB::verify_prehash(&pk, &digest_bad, &sig));
    }

    #[test]
    fn test_kyber_decapsulate_negative() {
        // Generate keypair and encapsulate
        let (pk, sk) = SimpleKem::generate_keypair().unwrap();
        let (mut ct, shared_secret) = SimpleKem::encapsulate(&pk).unwrap();
        assert_eq!(shared_secret.len(), KYBER_SHARED_SECRET_SIZE);
        // Corrupt one byte of ciphertext, ensure decap no longer matches
        if let Some(first) = ct.bytes.first_mut() { *first ^= 0xFF; }
        let dec = SimpleKem::decapsulate(&sk, &ct).unwrap();
        assert_ne!(dec, shared_secret);
    }

    #[test]
    fn test_x25519_kem() {
        // Test X25519 KEM operations
        let (pk, sk) = X25519Kem::generate_keypair().unwrap();
        assert_eq!(pk.as_bytes().len(), X25519_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), X25519_SECRET_KEY_SIZE);

        // Test encapsulation
        let (ct, shared_secret) = X25519Kem::encapsulate(&pk).unwrap();
        assert_eq!(ct.as_bytes().len(), X25519_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret.len(), X25519_SHARED_SECRET_SIZE);

        // Test decapsulation
        let decapsulated_secret = X25519Kem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(shared_secret, decapsulated_secret);
    }

    #[test]
    fn test_x25519_serialization() {
        // Test X25519 public key serialization
        let (pk, _sk) = X25519Kem::generate_keypair().unwrap();
        let pk_bytes = pk.as_bytes();
        let pk_restored = X25519PublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk, pk_restored);

        // Test X25519 ciphertext serialization
        let (ct, _ss) = X25519Kem::encapsulate(&pk).unwrap();
        let ct_bytes = ct.as_bytes();
        let ct_restored = X25519Ciphertext::from_bytes(ct_bytes).unwrap();
        assert_eq!(ct, ct_restored);
    }

    #[test]
    fn test_x25519_wrong_key() {
        // Test that decapsulation with wrong key gives different secret
        let (pk1, _sk1) = X25519Kem::generate_keypair().unwrap();
        let (_pk2, sk2) = X25519Kem::generate_keypair().unwrap();

        let (ct, ss1) = X25519Kem::encapsulate(&pk1).unwrap();
        let ss2 = X25519Kem::decapsulate(&sk2, &ct).unwrap();

        // Different keys should produce different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_hybrid_kem_basic() {
        // Test basic hybrid KEM operations
        let (pk, sk) = HybridKem::generate_keypair().unwrap();

        // Verify component sizes
        assert_eq!(pk.x25519_pk.as_bytes().len(), X25519_PUBLIC_KEY_SIZE);
        assert_eq!(pk.mlkem_pk.as_bytes().len(), KYBER_PUBLIC_KEY_SIZE);

        // Test encapsulation
        let (ct, shared_secret) = HybridKem::encapsulate(&pk).unwrap();
        assert_eq!(ct.x25519_ct.as_bytes().len(), X25519_CIPHERTEXT_SIZE);
        assert_eq!(ct.mlkem_ct.as_bytes().len(), KYBER_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret.len(), 32);

        // Test decapsulation
        let decapsulated_secret = HybridKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(shared_secret, decapsulated_secret);
    }

    #[test]
    fn test_hybrid_kem_deterministic() {
        // Test that hybrid KEM is deterministic for same inputs
        let (pk, sk) = HybridKem::generate_keypair().unwrap();
        let (ct1, ss1) = HybridKem::encapsulate(&pk).unwrap();
        let (ct2, ss2) = HybridKem::encapsulate(&pk).unwrap();

        // Different encapsulations should produce different ciphertexts and secrets
        // (due to randomness in both X25519 and ML-KEM)
        assert_ne!(ss1, ss2);
        assert_ne!(ct1.to_bytes(), ct2.to_bytes());

        // But decapsulation should be deterministic
        let dec1 = HybridKem::decapsulate(&sk, &ct1).unwrap();
        let dec2 = HybridKem::decapsulate(&sk, &ct2).unwrap();
        assert_eq!(ss1, dec1);
        assert_eq!(ss2, dec2);
    }

    #[test]
    fn test_hybrid_kem_serialization() {
        // Test hybrid public key serialization
        let (pk, _sk) = HybridKem::generate_keypair().unwrap();
        let pk_bytes = pk.to_bytes();
        let pk_restored = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, pk_restored);

        // Test hybrid ciphertext serialization
        let (ct, _ss) = HybridKem::encapsulate(&pk).unwrap();
        let ct_bytes = ct.to_bytes();
        let ct_restored = HybridCiphertext::from_bytes(&ct_bytes).unwrap();
        assert_eq!(ct, ct_restored);
    }

    #[test]
    fn test_hybrid_kem_wrong_key() {
        // Test that decapsulation with wrong key gives different secret
        let (pk1, _sk1) = HybridKem::generate_keypair().unwrap();
        let (_pk2, sk2) = HybridKem::generate_keypair().unwrap();

        let (ct, ss1) = HybridKem::encapsulate(&pk1).unwrap();
        let ss2 = HybridKem::decapsulate(&sk2, &ct).unwrap();

        // Different keys should produce different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_hybrid_kem_corrupted_ciphertext() {
        // Test that corrupted ciphertext produces different secret
        let (pk, sk) = HybridKem::generate_keypair().unwrap();
        let (mut ct, ss_original) = HybridKem::encapsulate(&pk).unwrap();

        // Corrupt X25519 component
        ct.x25519_ct.bytes[0] ^= 0xFF;
        let ss_corrupted = HybridKem::decapsulate(&sk, &ct).unwrap();
        assert_ne!(ss_original, ss_corrupted);
    }

    #[test]
    fn test_hybrid_oob_payment_basic() {
        // Test basic hybrid out-of-band payment
        let (recipient_pk, recipient_sk) = HybridKem::generate_keypair().unwrap();
        let note_metadata = b"test payment metadata with hybrid KEM";
        let associated_data = b"payment_context_v2";

        // Create payment
        let payment = HybridOutOfBandPayment::new(
            recipient_pk.clone(),
            note_metadata,
            associated_data.to_vec(),
        )
        .unwrap();

        // Verify payment structure
        payment.verify().unwrap();

        // Decrypt payment
        let decrypted_metadata = payment.decrypt(&recipient_sk).unwrap();
        assert_eq!(note_metadata.to_vec(), decrypted_metadata);
    }

    #[test]
    fn test_hybrid_oob_payment_serialization() {
        // Test serialization and deserialization of hybrid payment
        let (recipient_pk, recipient_sk) = HybridKem::generate_keypair().unwrap();
        let note_metadata = b"serialization test data";
        let associated_data = b"context";

        let payment = HybridOutOfBandPayment::new(
            recipient_pk.clone(),
            note_metadata,
            associated_data.to_vec(),
        )
        .unwrap();

        // Serialize
        let serialized = payment.to_bytes().unwrap();
        assert!(!serialized.is_empty());

        // Deserialize
        let deserialized = HybridOutOfBandPayment::from_bytes(&serialized).unwrap();

        // Verify deserialized payment can be decrypted
        let decrypted = deserialized.decrypt(&recipient_sk).unwrap();
        assert_eq!(note_metadata.to_vec(), decrypted);
    }

    #[test]
    fn test_hybrid_oob_payment_wrong_key() {
        // Test that wrong key cannot decrypt payment
        let (recipient_pk, _recipient_sk) = HybridKem::generate_keypair().unwrap();
        let (_other_pk, other_sk) = HybridKem::generate_keypair().unwrap();
        let note_metadata = b"secret payment data";
        let associated_data = b"context";

        let payment = HybridOutOfBandPayment::new(
            recipient_pk.clone(),
            note_metadata,
            associated_data.to_vec(),
        )
        .unwrap();

        // Try to decrypt with wrong key - should fail or produce garbage
        let result = payment.decrypt(&other_sk);
        // Decapsulation will succeed but AEAD decryption should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_oob_payment_large_metadata() {
        // Test with larger metadata payload
        let (recipient_pk, recipient_sk) = HybridKem::generate_keypair().unwrap();
        let note_metadata = vec![0x42u8; 10000]; // 10KB of data
        let associated_data = b"large_payload_test";

        let payment = HybridOutOfBandPayment::new(
            recipient_pk.clone(),
            &note_metadata,
            associated_data.to_vec(),
        )
        .unwrap();

        payment.verify().unwrap();

        let decrypted_metadata = payment.decrypt(&recipient_sk).unwrap();
        assert_eq!(note_metadata, decrypted_metadata);
    }

    #[test]
    fn test_hybrid_vs_legacy_independence() {
        // Test that hybrid and legacy systems are independent
        let (kyber_pk, kyber_sk) = SimpleKem::generate_keypair().unwrap();
        let (hybrid_pk, hybrid_sk) = HybridKem::generate_keypair().unwrap();

        let metadata = b"test data";
        let associated_data = b"context";

        // Create both types of payments
        let legacy_payment = OutOfBandPayment::new(
            kyber_pk,
            metadata,
            associated_data.to_vec(),
        )
        .unwrap();

        let hybrid_payment = HybridOutOfBandPayment::new(
            hybrid_pk,
            metadata,
            associated_data.to_vec(),
        )
        .unwrap();

        // Verify both can be decrypted with their respective keys
        let legacy_decrypted = legacy_payment.decrypt(&kyber_sk).unwrap();
        let hybrid_decrypted = hybrid_payment.decrypt(&hybrid_sk).unwrap();

        assert_eq!(legacy_decrypted, metadata.to_vec());
        assert_eq!(hybrid_decrypted, metadata.to_vec());
    }

    #[test]
    fn test_hybrid_kem_secret_combination() {
        // Test that the secret combination is properly mixing both secrets
        let (pk, sk) = HybridKem::generate_keypair().unwrap();
        let (ct, combined_ss) = HybridKem::encapsulate(&pk).unwrap();

        // Manually decapsulate both components
        let x25519_ss = X25519Kem::decapsulate(&sk.x25519_sk, &ct.x25519_ct).unwrap();
        let mlkem_ss = SimpleKem::decapsulate(&sk.mlkem_sk, &ct.mlkem_ct).unwrap();

        // Verify that the combined secret is not just one of the component secrets
        assert_ne!(&combined_ss[..], &x25519_ss[..]);
        assert_ne!(combined_ss, mlkem_ss);

        // Verify that manually combining gives the same result
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tachyon:hybrid_kem:v1");
        hasher.update(&x25519_ss);
        hasher.update(&mlkem_ss);
        let expected_combined = hasher.finalize();
        
        assert_eq!(&combined_ss[..], expected_combined.as_bytes());
    }

    #[test]
    fn test_hybrid_display_impls() {
        // Test Display implementations for debugging
        let (pk, _sk) = HybridKem::generate_keypair().unwrap();
        let pk_str = format!("{}", pk);
        assert!(pk_str.contains("HybridPublicKey"));

        let (ct, _ss) = HybridKem::encapsulate(&pk).unwrap();
        let ct_str = format!("{}", ct);
        assert!(ct_str.contains("HybridCiphertext"));

        let x25519_pk_str = format!("{}", pk.x25519_pk);
        assert!(x25519_pk_str.contains("X25519PublicKey"));
    }

    #[test]
    fn test_hybrid_payment_display() {
        // Test Display implementation for HybridOutOfBandPayment
        let (pk, _sk) = HybridKem::generate_keypair().unwrap();
        let payment = HybridOutOfBandPayment::new(
            pk,
            b"test",
            b"context".to_vec(),
        )
        .unwrap();

        let display_str = format!("{}", payment);
        assert!(display_str.contains("HybridOutOfBandPayment"));
    }
}
