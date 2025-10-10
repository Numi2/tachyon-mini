//! # storage
//!
//! Encrypted storage layer for Tachyon wallet.
//! Provides secure note database with encryption at rest and in-memory caching.

use anyhow::{anyhow, Result};
use fs2::FileExt;
use rand::RngCore;
use pq_crypto::{
    KyberPublicKey, KyberSecretKey, SimpleAead, SimpleKem, AES_KEY_SIZE, AES_NONCE_SIZE,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use tokio::fs;

/// Size of database master key (derived from user password)
pub const DB_MASTER_KEY_SIZE: usize = 32;

/// Note commitment hash size (BLAKE3 hash)
pub const NOTE_COMMITMENT_SIZE: usize = 32;

/// Encrypted note record in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// Encrypted note data (commitment + metadata + witness data)
    pub encrypted_data: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Position in the MMR accumulator
    pub position: u64,
    /// Block height when note was created
    pub block_height: u64,
    /// Whether this note has been spent
    pub is_spent: bool,
    /// Timestamp when note was added to wallet
    pub created_at: u64,
}

impl EncryptedNote {
    /// Create a new encrypted note
    pub fn new(
        position: u64,
        block_height: u64,
        note_data: &[u8],
        master_key: &[u8; DB_MASTER_KEY_SIZE],
    ) -> Result<Self> {
        let nonce = SimpleAead::generate_nonce();
        let associated_data = b"note_encryption";

        let encrypted_data = SimpleAead::encrypt(master_key, &nonce, note_data, associated_data)?;

        Ok(Self {
            encrypted_data,
            nonce,
            position,
            block_height,
            is_spent: false,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Decrypt the note data
    pub fn decrypt(&self, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<Vec<u8>> {
        let associated_data = b"note_encryption";
        if self.encrypted_data.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }
        if self.encrypted_data[..AES_NONCE_SIZE] != self.nonce {
            return Err(anyhow!("Nonce mismatch for EncryptedNote"));
        }
        SimpleAead::decrypt(master_key, &self.encrypted_data, associated_data)
    }

    /// Mark the note as spent
    pub fn mark_spent(&mut self) {
        self.is_spent = true;
    }

    /// Check if the note is spent
    pub fn is_spent(&self) -> bool {
        self.is_spent
    }
}

/// PCD state record in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcdStateRecord {
    /// Encrypted PCD state data
    pub encrypted_state: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Anchor height for this PCD state
    pub anchor_height: u64,
    /// State commitment hash
    pub state_commitment: [u8; 32],
    /// Proof data
    pub proof: Vec<u8>,
    /// Timestamp when state was recorded
    pub created_at: u64,
}

impl PcdStateRecord {
    /// Create a new PCD state record
    pub fn new(
        anchor_height: u64,
        state_commitment: [u8; 32],
        state_data: &[u8],
        proof: Vec<u8>,
        master_key: &[u8; DB_MASTER_KEY_SIZE],
    ) -> Result<Self> {
        let nonce = SimpleAead::generate_nonce();
        let associated_data = b"pcd_state_encryption";

        let encrypted_state = SimpleAead::encrypt(master_key, &nonce, state_data, associated_data)?;

        Ok(Self {
            encrypted_state,
            nonce,
            anchor_height,
            state_commitment,
            proof,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Decrypt the PCD state data
    pub fn decrypt_state(&self, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<Vec<u8>> {
        let associated_data = b"pcd_state_encryption";
        if self.encrypted_state.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }
        if self.encrypted_state[..AES_NONCE_SIZE] != self.nonce {
            return Err(anyhow!("Nonce mismatch for PcdStateRecord"));
        }
        SimpleAead::decrypt(master_key, &self.encrypted_state, associated_data)
    }

    /// Get the state commitment
    pub fn state_commitment(&self) -> &[u8; 32] {
        &self.state_commitment
    }

    /// Get the proof data
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Get the anchor height
    pub fn anchor_height(&self) -> u64 {
        self.anchor_height
    }
}

/// MMR witness record for efficient proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRecord {
    /// Note position in MMR
    pub position: u64,
    /// Encrypted witness data
    pub encrypted_witness: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Last update height
    pub last_update_height: u64,
    /// Timestamp when witness was recorded
    pub created_at: u64,
}

impl WitnessRecord {
    /// Create a new witness record
    pub fn new(
        position: u64,
        witness_data: &[u8],
        master_key: &[u8; DB_MASTER_KEY_SIZE],
    ) -> Result<Self> {
        let nonce = SimpleAead::generate_nonce();
        let associated_data = b"witness_encryption";

        let encrypted_witness =
            SimpleAead::encrypt(master_key, &nonce, witness_data, associated_data)?;

        Ok(Self {
            position,
            encrypted_witness,
            nonce,
            last_update_height: 0,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Decrypt the witness data
    pub fn decrypt_witness(&self, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<Vec<u8>> {
        let associated_data = b"witness_encryption";
        if self.encrypted_witness.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }
        if self.encrypted_witness[..AES_NONCE_SIZE] != self.nonce {
            return Err(anyhow!("Nonce mismatch for WitnessRecord"));
        }
        SimpleAead::decrypt(master_key, &self.encrypted_witness, associated_data)
    }

    /// Update the witness with new data
    pub fn update_witness(
        &mut self,
        new_witness_data: &[u8],
        master_key: &[u8; DB_MASTER_KEY_SIZE],
    ) -> Result<()> {
        let nonce = SimpleAead::generate_nonce();
        let associated_data = b"witness_encryption";

        self.encrypted_witness =
            SimpleAead::encrypt(master_key, &nonce, new_witness_data, associated_data)?;
        self.nonce = nonce;
        self.last_update_height += 1;

        Ok(())
    }
}

/// Main wallet database structure
pub struct WalletDatabase {
    /// Database path
    db_path: PathBuf,
    /// Master encryption key (derived from user password)
    pub master_key: [u8; DB_MASTER_KEY_SIZE],
    /// File handle for process-wide DB lock (kept open to hold lock)
    lock_file: File,
    /// In-memory note cache for performance
    note_cache: Arc<RwLock<HashMap<[u8; NOTE_COMMITMENT_SIZE], EncryptedNote>>>,
    /// In-memory PCD state cache
    pcd_state_cache: Arc<RwLock<Option<PcdStateRecord>>>,
    /// In-memory witness cache
    witness_cache: Arc<RwLock<HashMap<u64, WitnessRecord>>>,
    /// In-memory OOB keypair cache
    oob_keys_cache: Arc<RwLock<Option<OobKeysRecord>>>,
    /// In-memory spend secret cache (encrypted on disk)
    spend_secret_cache: Arc<RwLock<Option<SpendSecretRecord>>>,
}

impl WalletDatabase {
    /// Create a new wallet database
    pub async fn new(db_path: &Path, master_password: &str) -> Result<Self> {
        // Derive master key from password (in production, use proper KDF like Argon2)
        let master_key = Self::derive_master_key(master_password)?;

        // Create database directory
        fs::create_dir_all(db_path).await?;

        // Acquire process-wide lock file for this database to prevent concurrent writers
        let lock_path = db_path.join("db.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock_file.lock_exclusive()?;

        let mut db = Self {
            db_path: db_path.to_path_buf(),
            master_key,
            lock_file,
            note_cache: Arc::new(RwLock::new(HashMap::new())),
            pcd_state_cache: Arc::new(RwLock::new(None)),
            witness_cache: Arc::new(RwLock::new(HashMap::new())),
            oob_keys_cache: Arc::new(RwLock::new(None)),
            spend_secret_cache: Arc::new(RwLock::new(None)),
        };

        // Load existing data from disk
        db.load_from_disk().await?;

        Ok(db)
    }

    /// Derive master key from password using Argon2id
    fn derive_master_key(password: &str) -> Result<[u8; DB_MASTER_KEY_SIZE]> {
        use argon2::{Argon2, ParamsBuilder};
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Algorithm, Version};

        // Derive a deterministic salt from the password (for demo). In production, store a random salt.
        let mut h = blake3::Hasher::new();
        h.update(b"wallet_master_salt");
        h.update(password.as_bytes());
        let mut salt_bytes = [0u8; 16];
        salt_bytes.copy_from_slice(&h.finalize().as_bytes()[..16]);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|_| anyhow!("salt encode failed"))?;

        // Reasonable defaults; tune as needed.
        let params = ParamsBuilder::new()
            .m_cost(19456)
            .t_cost(2)
            .p_cost(1)
            .output_len(DB_MASTER_KEY_SIZE)
            .build()
            .map_err(|e| anyhow!("argon2 params error: {:?}", e))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let phc = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("argon2 hash error: {:?}", e))?;

        let out = phc.hash.ok_or_else(|| anyhow!("argon2 output missing"))?;
        let out_bytes = out.as_bytes();
        if out_bytes.len() < DB_MASTER_KEY_SIZE {
            return Err(anyhow!("argon2 output too short"));
        }
        let mut key = [0u8; DB_MASTER_KEY_SIZE];
        key.copy_from_slice(&out_bytes[..DB_MASTER_KEY_SIZE]);
        Ok(key)
    }

    /// Load database from disk
    async fn load_from_disk(&mut self) -> Result<()> {
        // Load notes
        let notes_path = self.db_path.join("notes.bin");
        if notes_path.exists() {
            let data = fs::read(&notes_path).await?;
            let notes: HashMap<[u8; NOTE_COMMITMENT_SIZE], EncryptedNote> =
                bincode::deserialize(&data)?;
            *self.note_cache.write().unwrap() = notes;
        }

        // Load PCD state
        let pcd_path = self.db_path.join("pcd_state.bin");
        if pcd_path.exists() {
            let data = fs::read(&pcd_path).await?;
            let pcd_state: PcdStateRecord = bincode::deserialize(&data)?;
            *self.pcd_state_cache.write().unwrap() = Some(pcd_state);
        }

        // Load witnesses
        let witnesses_path = self.db_path.join("witnesses.bin");
        if witnesses_path.exists() {
            let data = fs::read(&witnesses_path).await?;
            let witnesses: HashMap<u64, WitnessRecord> = bincode::deserialize(&data)?;
            *self.witness_cache.write().unwrap() = witnesses;
        }

        // Load OOB keys
        let keys_path = self.db_path.join("oob_keys.bin");
        if keys_path.exists() {
            let data = fs::read(&keys_path).await?;
            let keys: OobKeysRecord = bincode::deserialize(&data)?;
            *self.oob_keys_cache.write().unwrap() = Some(keys);
        }

        // Load spend secret
        let spend_path = self.db_path.join("spend_secret.bin");
        if spend_path.exists() {
            let data = fs::read(&spend_path).await?;
            let rec: SpendSecretRecord = bincode::deserialize(&data)?;
            *self.spend_secret_cache.write().unwrap() = Some(rec);
        }

        Ok(())
    }

    /// Save database to disk
    async fn save_to_disk(&self) -> Result<()> {
        // Ensure database directory exists (in case it was removed during runtime)
        fs::create_dir_all(&self.db_path).await?;
        // Save notes atomically
        let notes_path = self.db_path.join("notes.bin");
        let notes_tmp = self.db_path.join("notes.bin.tmp");
        let notes_data = {
            let notes = self.note_cache.read().unwrap();
            bincode::serialize(&*notes)?
        };
        fs::write(&notes_tmp, &notes_data).await?;
        fs::rename(&notes_tmp, &notes_path).await?;

        // Save PCD state atomically
        let pcd_path = self.db_path.join("pcd_state.bin");
        let pcd_state_opt = { self.pcd_state_cache.read().unwrap().clone() };
        if let Some(pcd_state) = pcd_state_opt {
            let pcd_tmp = self.db_path.join("pcd_state.bin.tmp");
            let pcd_data = bincode::serialize(&pcd_state)?;
            fs::write(&pcd_tmp, &pcd_data).await?;
            fs::rename(&pcd_tmp, &pcd_path).await?;
        }

        // Save witnesses atomically
        let witnesses_path = self.db_path.join("witnesses.bin");
        let witnesses_tmp = self.db_path.join("witnesses.bin.tmp");
        let witnesses_data = {
            let witnesses = self.witness_cache.read().unwrap();
            bincode::serialize(&*witnesses)?
        };
        fs::write(&witnesses_tmp, &witnesses_data).await?;
        fs::rename(&witnesses_tmp, &witnesses_path).await?;

        // Save OOB keys if present atomically
        let keys_path = self.db_path.join("oob_keys.bin");
        let keys_opt = { self.oob_keys_cache.read().unwrap().clone() };
        if let Some(keys) = keys_opt {
            let keys_tmp = self.db_path.join("oob_keys.bin.tmp");
            let keys_data = bincode::serialize(&keys)?;
            fs::write(&keys_tmp, &keys_data).await?;
            fs::rename(&keys_tmp, &keys_path).await?;
        }

        // Save spend secret if present atomically
        let spend_path = self.db_path.join("spend_secret.bin");
        let spend_opt = { self.spend_secret_cache.read().unwrap().clone() };
        if let Some(rec) = spend_opt {
            let tmp = self.db_path.join("spend_secret.bin.tmp");
            let data = bincode::serialize(&rec)?;
            fs::write(&tmp, &data).await?;
            fs::rename(&tmp, &spend_path).await?;
        }

        Ok(())
    }

    /// Flush in-memory state to disk
    pub async fn flush(&self) -> Result<()> {
        self.save_to_disk().await
    }

    /// Gracefully release the exclusive database lock.
    ///
    /// Note: Only call this when you are certain no other operations will run.
    pub fn release_lock(&self) -> Result<()> {
        fs2::FileExt::unlock(&self.lock_file)?;
        Ok(())
    }

    /// Add a new note to the database
    pub async fn add_note(
        &self,
        commitment: [u8; NOTE_COMMITMENT_SIZE],
        note: EncryptedNote,
    ) -> Result<()> {
        {
            let mut notes = self.note_cache.write().unwrap();
            notes.insert(commitment, note);
        }

        // Save to disk
        self.save_to_disk().await?;

        Ok(())
    }

    /// Get a note by commitment
    pub async fn get_note(&self, commitment: &[u8; NOTE_COMMITMENT_SIZE]) -> Option<EncryptedNote> {
        self.note_cache.read().unwrap().get(commitment).cloned()
    }

    /// List all notes
    pub async fn list_notes(&self) -> Vec<EncryptedNote> {
        self.note_cache.read().unwrap().values().cloned().collect()
    }

    /// List unspent notes
    pub async fn list_unspent_notes(&self) -> Vec<EncryptedNote> {
        self.note_cache
            .read()
            .unwrap()
            .values()
            .filter(|note| !note.is_spent)
            .cloned()
            .collect()
    }

    /// Update note spent status
    pub async fn update_note_spent_status(
        &self,
        commitment: &[u8; NOTE_COMMITMENT_SIZE],
        is_spent: bool,
    ) -> Result<()> {
        {
            let mut notes = self.note_cache.write().unwrap();
            if let Some(note) = notes.get_mut(commitment) {
                note.is_spent = is_spent;
            }
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Set PCD state
    pub async fn set_pcd_state(&self, pcd_state: PcdStateRecord) -> Result<()> {
        {
            *self.pcd_state_cache.write().unwrap() = Some(pcd_state);
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Get current PCD state
    pub async fn get_pcd_state(&self) -> Option<PcdStateRecord> {
        self.pcd_state_cache.read().unwrap().clone()
    }

    /// Add or update witness
    pub async fn upsert_witness(&self, position: u64, witness: WitnessRecord) -> Result<()> {
        {
            let mut witnesses = self.witness_cache.write().unwrap();
            witnesses.insert(position, witness);
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Get witness by position
    pub async fn get_witness(&self, position: u64) -> Option<WitnessRecord> {
        self.witness_cache.read().unwrap().get(&position).cloned()
    }

    /// Get all witnesses
    pub async fn list_witnesses(&self) -> Vec<WitnessRecord> {
        self.witness_cache
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Delete a note (for spent notes cleanup)
    pub async fn delete_note(&self, commitment: &[u8; NOTE_COMMITMENT_SIZE]) -> Result<()> {
        {
            let mut notes = self.note_cache.write().unwrap();
            notes.remove(commitment);
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> DatabaseStats {
        let notes = self.note_cache.read().unwrap();
        let unspent_notes = notes.values().filter(|note| !note.is_spent).count();
        let spent_notes = notes.len() - unspent_notes;

        DatabaseStats {
            total_notes: notes.len(),
            unspent_notes,
            spent_notes,
            has_pcd_state: self.pcd_state_cache.read().unwrap().is_some(),
            witness_count: self.witness_cache.read().unwrap().len(),
        }
    }

    /// Get persisted OOB keypair, if any
    pub async fn get_oob_keypair(&self) -> Result<Option<(KyberPublicKey, KyberSecretKey)>> {
        if let Some(keys) = self.oob_keys_cache.read().unwrap().as_ref() {
            let sk_bytes = keys.decrypt_secret(&self.master_key)?;
            let pk = KyberPublicKey::new(keys.public_key.clone());
            let sk = KyberSecretKey::new(sk_bytes);
            return Ok(Some((pk, sk)));
        }
        Ok(None)
    }

    /// Set (persist) OOB keypair
    pub async fn set_oob_keypair(&self, pk: &KyberPublicKey, sk: &KyberSecretKey) -> Result<()> {
        let keys = OobKeysRecord::new(pk, sk, &self.master_key)?;
        {
            *self.oob_keys_cache.write().unwrap() = Some(keys);
        }
        self.save_to_disk().await?;
        Ok(())
    }

    /// Get existing OOB keypair or generate and persist a new one
    pub async fn get_or_generate_oob_keypair(&self) -> Result<(KyberPublicKey, KyberSecretKey)> {
        if let Some((pk, sk)) = self.get_oob_keypair().await? {
            return Ok((pk, sk));
        }
        let (pk, sk) = SimpleKem::generate_keypair()?;
        self.set_oob_keypair(&pk, &sk).await?;
        Ok((pk, sk))
    }

    /// Get or generate a spend secret (32 bytes) encrypted at rest
    pub async fn get_or_generate_spend_secret(&self) -> Result<[u8; 32]> {
        if let Some(rec) = self.spend_secret_cache.read().unwrap().as_ref() {
            return rec.decrypt(&self.master_key);
        }
        // Generate new random spend secret
        let mut sec = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sec);
        let rec = SpendSecretRecord::new(&sec, &self.master_key)?;
        {
            *self.spend_secret_cache.write().unwrap() = Some(rec);
        }
        self.save_to_disk().await?;
        Ok(sec)
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_notes: usize,
    pub unspent_notes: usize,
    pub spent_notes: usize,
    pub has_pcd_state: bool,
    pub witness_count: usize,
}

/// Persisted OOB keypair (secret is encrypted at rest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobKeysRecord {
    /// Encrypted secret key bytes (nonce + ciphertext)
    pub encrypted_secret: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Public key bytes
    pub public_key: Vec<u8>,
}

impl OobKeysRecord {
    pub fn new(
        pk: &KyberPublicKey,
        sk: &KyberSecretKey,
        master_key: &[u8; DB_MASTER_KEY_SIZE],
    ) -> Result<Self> {
        let nonce = SimpleAead::generate_nonce();
        let encrypted_secret = SimpleAead::encrypt(master_key, &nonce, sk.as_bytes(), b"oob_keys")?;
        Ok(Self {
            encrypted_secret,
            nonce,
            public_key: pk.as_bytes().to_vec(),
        })
    }

    pub fn decrypt_secret(&self, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<Vec<u8>> {
        if self.encrypted_secret.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }
        if self.encrypted_secret[..AES_NONCE_SIZE] != self.nonce {
            return Err(anyhow!("Nonce mismatch for OobKeysRecord"));
        }
        let sk = SimpleAead::decrypt(master_key, &self.encrypted_secret, b"oob_keys")?;
        Ok(sk)
    }
}

/// Persisted spend secret (spend-authority key seed), encrypted at rest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendSecretRecord {
    /// Encrypted secret (nonce + ciphertext)
    pub encrypted_secret: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
}

impl SpendSecretRecord {
    pub fn new(spend_secret32: &[u8; 32], master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<Self> {
        let nonce = SimpleAead::generate_nonce();
        let encrypted_secret = SimpleAead::encrypt(master_key, &nonce, spend_secret32, b"spend_secret")?;
        Ok(Self { encrypted_secret, nonce })
    }

    pub fn decrypt(&self, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<[u8; 32]> {
        if self.encrypted_secret.len() < AES_NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }
        if self.encrypted_secret[..AES_NONCE_SIZE] != self.nonce {
            return Err(anyhow!("Nonce mismatch for SpendSecretRecord"));
        }
        let bytes = SimpleAead::decrypt(master_key, &self.encrypted_secret, b"spend_secret")?;
        if bytes.len() != 32 { return Err(anyhow!("Spend secret wrong length")); }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

impl Drop for WalletDatabase {
    fn drop(&mut self) {
        // Best-effort unlock; dropping the file will also release the lock
        let _ = fs2::FileExt::unlock(&self.lock_file);
    }
}

/// Database key derivation utilities
pub mod key_derivation {
    use super::*;

    /// Derive a note-specific encryption key from the master key and commitment
    pub fn derive_note_key(
        master_key: &[u8; DB_MASTER_KEY_SIZE],
        commitment: &[u8; NOTE_COMMITMENT_SIZE],
    ) -> [u8; AES_KEY_SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"note_key_derivation");
        hasher.update(master_key);
        hasher.update(commitment);

        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..AES_KEY_SIZE]);
        key
    }

    /// Derive a deterministic nonce for note encryption
    pub fn derive_note_nonce(
        master_key: &[u8; DB_MASTER_KEY_SIZE],
        commitment: &[u8; NOTE_COMMITMENT_SIZE],
    ) -> [u8; AES_NONCE_SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"note_nonce_derivation");
        hasher.update(master_key);
        hasher.update(commitment);

        let mut nonce = [0u8; AES_NONCE_SIZE];
        nonce.copy_from_slice(&hasher.finalize().as_bytes()[..AES_NONCE_SIZE]);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wallet_db");

        let db = WalletDatabase::new(&db_path, "test_password")
            .await
            .unwrap();
        let stats = db.get_stats().await;

        assert_eq!(stats.total_notes, 0);
        assert_eq!(stats.unspent_notes, 0);
        assert_eq!(stats.spent_notes, 0);
        assert!(!stats.has_pcd_state);
        assert_eq!(stats.witness_count, 0);
    }

    #[tokio::test]
    async fn test_note_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wallet_db");
        let db = WalletDatabase::new(&db_path, "test_password")
            .await
            .unwrap();

        let commitment = [1u8; NOTE_COMMITMENT_SIZE];
        let note_data = b"test note data";
        let note = EncryptedNote::new(0, 100, note_data, &db.master_key).unwrap();

        // Add note
        db.add_note(commitment, note.clone()).await.unwrap();

        // Retrieve note
        let retrieved_note = db.get_note(&commitment).await.unwrap();
        assert_eq!(retrieved_note.position, note.position);
        assert_eq!(retrieved_note.block_height, note.block_height);

        // List notes
        let notes = db.list_notes().await;
        assert_eq!(notes.len(), 1);

        // List unspent notes
        let unspent_notes = db.list_unspent_notes().await;
        assert_eq!(unspent_notes.len(), 1);

        // Mark as spent
        db.update_note_spent_status(&commitment, true)
            .await
            .unwrap();
        let unspent_notes = db.list_unspent_notes().await;
        assert_eq!(unspent_notes.len(), 0);

        // Delete note
        db.delete_note(&commitment).await.unwrap();
        let notes = db.list_notes().await;
        assert_eq!(notes.len(), 0);
    }

    #[tokio::test]
    async fn test_pcd_state() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wallet_db");
        let db = WalletDatabase::new(&db_path, "test_password")
            .await
            .unwrap();

        let state_commitment = [2u8; 32];
        let state_data = b"test pcd state";
        let proof = b"test proof".to_vec();

        let pcd_state =
            PcdStateRecord::new(200, state_commitment, state_data, proof, &db.master_key).unwrap();

        // Set PCD state
        db.set_pcd_state(pcd_state.clone()).await.unwrap();

        // Retrieve PCD state
        let retrieved_state = db.get_pcd_state().await.unwrap();
        assert_eq!(retrieved_state.anchor_height, pcd_state.anchor_height);
        assert_eq!(retrieved_state.state_commitment, pcd_state.state_commitment);
    }

    #[tokio::test]
    async fn test_witness_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wallet_db");
        let db = WalletDatabase::new(&db_path, "test_password")
            .await
            .unwrap();

        let witness_data = b"test witness data";
        let witness = WitnessRecord::new(42, witness_data, &db.master_key).unwrap();

        // Add witness
        db.upsert_witness(42, witness.clone()).await.unwrap();

        // Retrieve witness
        let retrieved_witness = db.get_witness(42).await.unwrap();
        assert_eq!(retrieved_witness.position, witness.position);

        // List witnesses
        let witnesses = db.list_witnesses().await;
        assert_eq!(witnesses.len(), 1);
    }

    #[tokio::test]
    async fn test_encryption_decryption() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("wallet_db");
        let db = WalletDatabase::new(&db_path, "test_password")
            .await
            .unwrap();

        let note_data = b"sensitive note data";
        let note = EncryptedNote::new(0, 100, note_data, &db.master_key).unwrap();

        // Decrypt the note
        let decrypted_data = note.decrypt(&db.master_key).unwrap();
        assert_eq!(note_data.to_vec(), decrypted_data);
    }
}
