//! # pq_crypto
//!
//! Post-quantum cryptography utilities for Tachyon.
//! Provides KEM (Key Encapsulation Mechanism) and AEAD encryption for out-of-band payments.

use anyhow::{anyhow, Result};
use rand::RngCore;
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
            .unwrap()
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
        let epoch_diff = if current_epoch.epoch > self.epoch_tag.epoch {
            current_epoch.epoch - self.epoch_tag.epoch
        } else {
            self.epoch_tag.epoch - current_epoch.epoch
        };

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
        let token_id = rand::random::<[u8; 16]>();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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
            .unwrap()
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
            .unwrap()
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
            .unwrap()
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
            padding = (0..padding_size).map(|_| rand::random::<u8>()).collect();
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
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
}

/// Out-of-band payment data structure
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
        let (kem_ciphertext, shared_secret) = SimpleKem::encapsulate(&recipient_pk)?;
        let nonce = SimpleAead::generate_nonce();

        let encrypted_metadata =
            SimpleAead::encrypt(&shared_secret, &nonce, note_metadata, &associated_data)?;

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
        let shared_secret = SimpleKem::decapsulate(recipient_sk, &self.kem_ciphertext)?;

        SimpleAead::decrypt(
            &shared_secret,
            &self.encrypted_metadata,
            &self.associated_data,
        )
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

/// Generate a random AES key
pub fn generate_aes_key() -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
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
        use pqcrypto_dilithium::dilithium3;
        let (pk, sk) = dilithium3::keypair();
        Ok((SuiteBPublicKey::new(pk.as_bytes().to_vec()), SuiteBSecretKey::new(sk.as_bytes().to_vec())))
    }

    /// Sign a prehashed 32-byte digest
    pub fn sign_prehash(secret_key: &SuiteBSecretKey, digest32: &[u8; 32]) -> Result<SuiteBSignature> {
        use pqcrypto_dilithium::dilithium3;
        let sk = dilithium3::SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|_| anyhow!("Invalid Suite B secret key bytes"))?;
        let sig = dilithium3::detached_sign(digest32, &sk);
        Ok(SuiteBSignature::new(sig.as_bytes().to_vec()))
    }

    /// Verify a signature over a prehashed 32-byte digest
    pub fn verify_prehash(public_key: &SuiteBPublicKey, digest32: &[u8; 32], signature: &SuiteBSignature) -> bool {
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
}
