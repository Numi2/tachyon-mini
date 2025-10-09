//! # pq_crypto
//!
//! Post-quantum cryptography utilities for Tachyon.
//! Provides KEM (Key Encapsulation Mechanism) and AEAD encryption for out-of-band payments.

use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

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
            return Err(anyhow!("Invalid public key size: expected {}, got {}", KYBER_PUBLIC_KEY_SIZE, bytes.len()));
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
            return Err(anyhow!("Invalid ciphertext size: expected {}, got {}", KYBER_CIPHERTEXT_SIZE, bytes.len()));
        }
        Ok(Self::new(bytes.to_vec()))
    }
}

impl fmt::Display for KyberCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KyberCiphertext({})", hex::encode(&self.bytes[..8]))
    }
}

/// Simple KEM implementation (placeholder for Kyber)
pub struct SimpleKem;

impl SimpleKem {
    /// Generate a keypair
    pub fn generate_keypair() -> Result<(KyberPublicKey, KyberSecretKey)> {
        let mut rng = rand::thread_rng();

        let mut sk_bytes = vec![0u8; KYBER_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut sk_bytes);

        let mut pk_bytes = vec![0u8; KYBER_PUBLIC_KEY_SIZE];
        rng.fill_bytes(&mut pk_bytes);

        Ok((
            KyberPublicKey::new(pk_bytes),
            KyberSecretKey::new(sk_bytes),
        ))
    }

    /// Encapsulate
    pub fn encapsulate(pk: &KyberPublicKey) -> Result<(KyberCiphertext, [u8; KYBER_SHARED_SECRET_SIZE])> {
        let mut rng = rand::thread_rng();
        let mut shared_secret = [0u8; KYBER_SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret);

        let mut ct_bytes = vec![0u8; KYBER_CIPHERTEXT_SIZE];
        rng.fill_bytes(&mut ct_bytes);

        Ok((
            KyberCiphertext::new(ct_bytes),
            shared_secret,
        ))
    }

    /// Decapsulate
    pub fn decapsulate(sk: &KyberSecretKey, ct: &KyberCiphertext) -> Result<[u8; KYBER_SHARED_SECRET_SIZE]> {
        let mut shared_secret = [0u8; KYBER_SHARED_SECRET_SIZE];
        // Simple derivation for testing
        let mut hasher = blake3::Hasher::new();
        hasher.update(sk.as_bytes());
        hasher.update(ct.as_bytes());
        shared_secret.copy_from_slice(&hasher.finalize().as_bytes()[..KYBER_SHARED_SECRET_SIZE]);
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
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use aes_gcm::aead::{Aead, KeyInit};

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce_obj = Nonce::from_slice(nonce);

        let mut ciphertext = cipher.encrypt(nonce_obj, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        }).map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

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
        use aes_gcm::{Aes256Gcm, Key};
        use aes_gcm::aead::{Aead, KeyInit};

        if ciphertext.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        let nonce = &ciphertext[..AES_NONCE_SIZE];
        let encrypted_data = &ciphertext[AES_NONCE_SIZE..];

        let plaintext = cipher.decrypt(nonce.into(), aes_gcm::aead::Payload {
            msg: encrypted_data,
            aad: associated_data,
        }).map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

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

        let encrypted_metadata = SimpleAead::encrypt(&shared_secret, &nonce, note_metadata, &associated_data)?;

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

        SimpleAead::decrypt(&shared_secret, &self.encrypted_metadata, &self.associated_data)
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

        let payment = OutOfBandPayment::new(recipient_pk.clone(), note_metadata, associated_data.to_vec()).unwrap();
        payment.verify().unwrap();

        let decrypted_metadata = payment.decrypt(&recipient_sk).unwrap();
        assert_eq!(note_metadata.to_vec(), decrypted_metadata);
    }
}
