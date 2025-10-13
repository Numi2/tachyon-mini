//! # storage
//!
//! Encrypted storage layer for Tachyon wallet.
//! Provides secure note database with encryption at rest and in-memory caching.

pub mod error;

use anyhow::{anyhow, Result};
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;
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
                .unwrap_or(std::time::Duration::from_secs(0))
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
                .unwrap_or(std::time::Duration::from_secs(0))
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
                .unwrap_or(std::time::Duration::from_secs(0))
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
    /// In-memory token ledger (generalized balances)
    token_ledger: Arc<RwLock<TokenLedger>>, 
    /// In-memory Zcash seed cache (encrypted on disk)
    zcash_seed_cache: Arc<RwLock<Option<ZcashSeedRecord>>>,
    /// Persistent DEX owner id (wallet-scoped)
    dex_owner_id: Arc<RwLock<Option<u64>>>,
    /// Last chain nullifier scan height (persisted)
    last_chain_nf_height: Arc<RwLock<u64>>,
}

impl WalletDatabase {
    /// Create a new wallet database
    pub async fn new(db_path: &Path, master_password: &str) -> Result<Self> {
        // Input validation
        if master_password.is_empty() && std::env::var("TACHYON_ALLOW_INSECURE").unwrap_or_default() != "1" {
            return Err(anyhow!("master password must not be empty"));
        }
        // Ensure database directory exists first (for salt file)
        fs::create_dir_all(db_path).await?;

        // Derive master key from password using Argon2id with per-db random salt (migrates if needed)
        let (master_key, maybe_legacy_key) = Self::derive_master_key(db_path, master_password)?;

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
            token_ledger: Arc::new(RwLock::new(TokenLedger::default())),
            zcash_seed_cache: Arc::new(RwLock::new(None)),
            dex_owner_id: Arc::new(RwLock::new(None)),
            last_chain_nf_height: Arc::new(RwLock::new(0)),
        };

        // Load existing data from disk
        db.load_from_disk().await?;

        // If we have a legacy key (salt was newly created) and there is existing encrypted data,
        // migrate all encrypted records to the new master key and persist.
        if let Some(mut legacy_key) = maybe_legacy_key {
            let has_existing = {
                let notes = db.note_cache.read().map_err(|_| anyhow!("Lock poisoned: note_cache"))?;
                let pcd = db.pcd_state_cache.read().map_err(|_| anyhow!("Lock poisoned: pcd_state_cache"))?;
                let wits = db.witness_cache.read().map_err(|_| anyhow!("Lock poisoned: witness_cache"))?;
                let oob = db.oob_keys_cache.read().map_err(|_| anyhow!("Lock poisoned: oob_keys_cache"))?;
                let spend = db.spend_secret_cache.read().map_err(|_| anyhow!("Lock poisoned: spend_secret_cache"))?;
                let zseed = db.zcash_seed_cache.read().map_err(|_| anyhow!("Lock poisoned: zcash_seed_cache"))?;
                !notes.is_empty() || pcd.is_some() || !wits.is_empty() || oob.is_some() || spend.is_some() || zseed.is_some()
            };

            if has_existing {
                // Migrate notes
                {
                    let mut new_map: HashMap<[u8; NOTE_COMMITMENT_SIZE], EncryptedNote> = HashMap::new();
                    let old_map = db.note_cache.read()
                        .map_err(|_| anyhow!("Lock poisoned: note_cache during migration"))?
                        .clone();
                    for (cm, enc) in old_map.into_iter() {
                        if let Ok(plaintext) = enc.decrypt(&legacy_key) {
                            if let Ok(new_rec) = EncryptedNote::new(enc.position, enc.block_height, &plaintext, &db.master_key) {
                                new_map.insert(cm, new_rec);
                            } else {
                                new_map.insert(cm, enc); // keep old if re-encrypt fails
                            }
                        } else {
                            new_map.insert(cm, enc);
                        }
                    }
                    *db.note_cache.write()
                        .map_err(|_| anyhow!("Lock poisoned: note_cache write during migration"))? = new_map;
                }

                // Migrate PCD state
                if let Some(rec) = db.pcd_state_cache.read()
                    .map_err(|_| anyhow!("Lock poisoned: pcd_state_cache during migration"))?
                    .clone() {
                    if let Ok(state_bytes) = rec.decrypt_state(&legacy_key) {
                        let new_rec = PcdStateRecord::new(
                            rec.anchor_height,
                            rec.state_commitment,
                            &state_bytes,
                            rec.proof.clone(),
                            &db.master_key,
                        )?;
                        *db.pcd_state_cache.write()
                            .map_err(|_| anyhow!("Lock poisoned: pcd_state_cache write during migration"))? = Some(new_rec);
                    }
                }

                // Migrate witnesses
                {
                    let mut new_wits: HashMap<u64, WitnessRecord> = HashMap::new();
                    let old_wits = db.witness_cache.read()
                        .map_err(|_| anyhow!("Lock poisoned: witness_cache during migration"))?
                        .clone();
                    for (pos, enc) in old_wits.into_iter() {
                        if let Ok(plaintext) = enc.decrypt_witness(&legacy_key) {
                            if let Ok(new_rec) = WitnessRecord::new(pos, &plaintext, &db.master_key) {
                                new_wits.insert(pos, new_rec);
                            } else {
                                new_wits.insert(pos, enc);
                            }
                        } else {
                            new_wits.insert(pos, enc);
                        }
                    }
                    *db.witness_cache.write()
                        .map_err(|_| anyhow!("Lock poisoned: witness_cache write during migration"))? = new_wits;
                }

                // Migrate OOB keys
                if let Some(keys) = db.oob_keys_cache.read()
                    .map_err(|_| anyhow!("Lock poisoned: oob_keys_cache during migration"))?
                    .clone() {
                    if let Ok(sk_bytes) = keys.decrypt_secret(&legacy_key) {
                        let pk = KyberPublicKey::new(keys.public_key.clone());
                        let sk = KyberSecretKey::new(sk_bytes);
                        let new_keys = OobKeysRecord::new(&pk, &sk, &db.master_key)?;
                        *db.oob_keys_cache.write()
                            .map_err(|_| anyhow!("Lock poisoned: oob_keys_cache write during migration"))? = Some(new_keys);
                    }
                }

                // Migrate spend secret
                if let Some(spend) = db.spend_secret_cache.read()
                    .map_err(|_| anyhow!("Lock poisoned: spend_secret_cache during migration"))?
                    .clone() {
                    if let Ok(sec) = spend.decrypt(&legacy_key) {
                        let new_rec = SpendSecretRecord::new(&sec, &db.master_key)?;
                        *db.spend_secret_cache.write()
                            .map_err(|_| anyhow!("Lock poisoned: spend_secret_cache write during migration"))? = Some(new_rec);
                    }
                }

                // Migrate Zcash seed
                if let Some(zrec) = db.zcash_seed_cache.read()
                    .map_err(|_| anyhow!("Lock poisoned: zcash_seed_cache during migration"))?
                    .clone() {
                    if let Ok(mnemonic) = zrec.decrypt_mnemonic(&legacy_key) {
                        let new_rec = ZcashSeedRecord::new(&mnemonic, zrec.birthday_height, &db.master_key)?;
                        *db.zcash_seed_cache.write()
                            .map_err(|_| anyhow!("Lock poisoned: zcash_seed_cache write during migration"))? = Some(new_rec);
                    }
                }

                // Persist migrated data
                db.save_to_disk().await?;
            }

            // Zeroize legacy key material
            legacy_key.zeroize();
        }

        Ok(db)
    }

    /// Derive master key from password using Argon2id and per-db salt.
    /// Returns (new_key, maybe_legacy_key) where legacy is Some if a migration may be needed.
    fn derive_master_key(db_path: &Path, password: &str) -> Result<([u8; DB_MASTER_KEY_SIZE], Option<[u8; DB_MASTER_KEY_SIZE]>)> {
        use argon2::{Argon2, ParamsBuilder};
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Algorithm, Version};

        // Salt file path
        let salt_path = db_path.join("salt.bin");
        let mut created_new_salt = false;
        let salt_bytes: [u8; 16] = if salt_path.exists() {
            let bytes = std::fs::read(&salt_path)?;
            if bytes.len() != 16 { return Err(anyhow!("invalid salt file length")); }
            let mut s = [0u8; 16];
            s.copy_from_slice(&bytes);
            s
        } else {
            let mut s = [0u8; 16];
            OsRng.fill_bytes(&mut s);
            // Best-effort atomic write
            let tmp = db_path.join("salt.bin.tmp");
            std::fs::write(&tmp, s)?;
            std::fs::rename(&tmp, &salt_path)?;
            created_new_salt = true;
            s
        };

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

        // If we just created a new random salt, compute legacy deterministic key for migration
        let legacy = if created_new_salt {
            Some(Self::derive_legacy_master_key(password)?)
        } else { None };

        Ok((key, legacy))
    }

    /// Legacy deterministic-salt derivation used by earlier versions (for migration only).
    fn derive_legacy_master_key(password: &str) -> Result<[u8; DB_MASTER_KEY_SIZE]> {
        use argon2::{Argon2, ParamsBuilder};
        use argon2::password_hash::{PasswordHasher, SaltString};
        use argon2::{Algorithm, Version};

        let mut h = blake3::Hasher::new();
        h.update(b"wallet_master_salt");
        h.update(password.as_bytes());
        let mut salt_bytes = [0u8; 16];
        salt_bytes.copy_from_slice(&h.finalize().as_bytes()[..16]);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|_| anyhow!("salt encode failed"))?;

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
            *self.note_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: note_cache during load"))? = notes;
        }

        // Load PCD state
        let pcd_path = self.db_path.join("pcd_state.bin");
        if pcd_path.exists() {
            let data = fs::read(&pcd_path).await?;
            let pcd_state: PcdStateRecord = bincode::deserialize(&data)?;
            *self.pcd_state_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: pcd_state_cache during load"))? = Some(pcd_state);
        }

        // Load witnesses
        let witnesses_path = self.db_path.join("witnesses.bin");
        if witnesses_path.exists() {
            let data = fs::read(&witnesses_path).await?;
            let witnesses: HashMap<u64, WitnessRecord> = bincode::deserialize(&data)?;
            *self.witness_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: witness_cache during load"))? = witnesses;
        }

        // Load OOB keys
        let keys_path = self.db_path.join("oob_keys.bin");
        if keys_path.exists() {
            let data = fs::read(&keys_path).await?;
            let keys: OobKeysRecord = bincode::deserialize(&data)?;
            *self.oob_keys_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: oob_keys_cache during load"))? = Some(keys);
        }

        // Load spend secret
        let spend_path = self.db_path.join("spend_secret.bin");
        if spend_path.exists() {
            let data = fs::read(&spend_path).await?;
            let rec: SpendSecretRecord = bincode::deserialize(&data)?;
            *self.spend_secret_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: spend_secret_cache during load"))? = Some(rec);
        }

        // Load Zcash seed
        let zcash_seed_path = self.db_path.join("zcash_seed.bin");
        if zcash_seed_path.exists() {
            let data = fs::read(&zcash_seed_path).await?;
            let rec: ZcashSeedRecord = bincode::deserialize(&data)?;
            *self.zcash_seed_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: zcash_seed_cache during load"))? = Some(rec);
        }

        // Load token ledger v2 (preferred), or migrate legacy balances if present
        let ledger_v2_path = self.db_path.join("balances_v2.bin");
        if ledger_v2_path.exists() {
            let data = fs::read(&ledger_v2_path).await?;
            let ledger: TokenLedger = bincode::deserialize(&data)?;
            *self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger during load"))? = ledger;
        } else {
            let legacy_path = self.db_path.join("balances.bin");
            if legacy_path.exists() {
                let data = fs::read(&legacy_path).await?;
                if let Ok(legacy) = bincode::deserialize::<TokenBalancesLegacy>(&data) {
                    let mut ledger = TokenLedger::default();
                    ledger.set_meta(TOKEN_USDC.to_string(), TokenMeta { decimals: 6 });
                    ledger.set_meta(TOKEN_BASE.to_string(), TokenMeta { decimals: 0 });
                    ledger.set_balance(TOKEN_USDC, legacy.usdc, legacy.usdc_locked);
                    ledger.set_balance(TOKEN_BASE, legacy.base, legacy.base_locked);
                    *self.token_ledger.write()
                        .map_err(|_| anyhow!("Lock poisoned: token_ledger during migration"))? = ledger;
                    // Persist migrated v2
                    let tmp = self.db_path.join("balances_v2.bin.tmp");
                    let data = bincode::serialize(&*self.token_ledger.read()
                        .map_err(|_| anyhow!("Lock poisoned: token_ledger during migration"))?)?;
                    fs::write(&tmp, &data).await?;
                    fs::rename(&tmp, &ledger_v2_path).await?;
                }
            }
        }

        // Load DEX owner id
        let dex_owner_path = self.db_path.join("dex_owner_id.bin");
        if dex_owner_path.exists() {
            let data = fs::read(&dex_owner_path).await?;
            if let Ok(id) = bincode::deserialize::<u64>(&data) {
                *self.dex_owner_id.write()
                    .map_err(|_| anyhow!("Lock poisoned: dex_owner_id during load"))? = Some(id);
            }
        }

        // Load last chain nullifier scan height
        let nf_h_path = self.db_path.join("last_chain_nf_height.bin");
        if nf_h_path.exists() {
            let data = fs::read(&nf_h_path).await?;
            if let Ok(h) = bincode::deserialize::<u64>(&data) {
                *self.last_chain_nf_height.write()
                    .map_err(|_| anyhow!("Lock poisoned: last_chain_nf_height during load"))? = h;
            }
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
            let notes = self.note_cache.read()
                .map_err(|_| anyhow!("Lock poisoned: note_cache"))?;
            bincode::serialize(&*notes)?
        };
        fs::write(&notes_tmp, &notes_data).await?;
        fs::rename(&notes_tmp, &notes_path).await?;

        // Save PCD state atomically
        let pcd_path = self.db_path.join("pcd_state.bin");
        let pcd_state_opt = {
            self.pcd_state_cache.read()
                .map_err(|_| anyhow!("Lock poisoned: pcd_state_cache"))?
                .clone()
        };
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
            let witnesses = self.witness_cache.read()
                .map_err(|_| anyhow!("Lock poisoned: witness_cache"))?;
            bincode::serialize(&*witnesses)?
        };
        fs::write(&witnesses_tmp, &witnesses_data).await?;
        fs::rename(&witnesses_tmp, &witnesses_path).await?;

        // Save OOB keys if present atomically
        let keys_path = self.db_path.join("oob_keys.bin");
        let keys_opt = {
            self.oob_keys_cache.read()
                .map_err(|_| anyhow!("Lock poisoned: oob_keys_cache"))?
                .clone()
        };
        if let Some(keys) = keys_opt {
            let keys_tmp = self.db_path.join("oob_keys.bin.tmp");
            let keys_data = bincode::serialize(&keys)?;
            fs::write(&keys_tmp, &keys_data).await?;
            fs::rename(&keys_tmp, &keys_path).await?;
        }

        // Save spend secret if present atomically
        let spend_path = self.db_path.join("spend_secret.bin");
        let spend_opt = {
            self.spend_secret_cache.read()
                .map_err(|_| anyhow!("Lock poisoned: spend_secret_cache"))?
                .clone()
        };
        if let Some(rec) = spend_opt {
            let tmp = self.db_path.join("spend_secret.bin.tmp");
            let data = bincode::serialize(&rec)?;
            fs::write(&tmp, &data).await?;
            fs::rename(&tmp, &spend_path).await?;
        }

        // Save Zcash seed if present atomically
        let zcash_seed_path = self.db_path.join("zcash_seed.bin");
        let zcash_seed_opt = {
            self.zcash_seed_cache.read()
                .map_err(|_| anyhow!("Lock poisoned: zcash_seed_cache"))?
                .clone()
        };
        if let Some(rec) = zcash_seed_opt {
            let tmp = self.db_path.join("zcash_seed.bin.tmp");
            let data = bincode::serialize(&rec)?;
            fs::write(&tmp, &data).await?;
            fs::rename(&tmp, &zcash_seed_path).await?;
        }

        // Save token ledger v2 atomically
        let ledger_v2_path = self.db_path.join("balances_v2.bin");
        let ledger_tmp = self.db_path.join("balances_v2.bin.tmp");
        let ledger_data = {
            let ledger = self.token_ledger.read()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            bincode::serialize(&*ledger)?
        };
        fs::write(&ledger_tmp, &ledger_data).await?;
        fs::rename(&ledger_tmp, &ledger_v2_path).await?;

        // Save DEX owner id if present atomically
        let dex_owner_opt = {
            *self.dex_owner_id.read()
                .map_err(|_| anyhow!("Lock poisoned: dex_owner_id"))?
        };
        if let Some(id) = dex_owner_opt {
            let dex_owner_path = self.db_path.join("dex_owner_id.bin");
            let dex_owner_tmp = self.db_path.join("dex_owner_id.bin.tmp");
            let data = bincode::serialize(&id)?;
            fs::write(&dex_owner_tmp, &data).await?;
            fs::rename(&dex_owner_tmp, &dex_owner_path).await?;
        }

        // Save last chain nullifier height atomically
        let nf_h = {
            *self.last_chain_nf_height.read()
                .map_err(|_| anyhow!("Lock poisoned: last_chain_nf_height"))?
        };
        let nf_h_path = self.db_path.join("last_chain_nf_height.bin");
        let nf_h_tmp = self.db_path.join("last_chain_nf_height.bin.tmp");
        let data = bincode::serialize(&nf_h)?;
        fs::write(&nf_h_tmp, &data).await?;
        fs::rename(&nf_h_tmp, &nf_h_path).await?;

        Ok(())
    }

    /// Get or create a persistent DEX owner id for this wallet
    pub async fn get_or_create_dex_owner_id(&self) -> Result<u64> {
        if let Some(id) = *self.dex_owner_id.read()
            .map_err(|_| anyhow!("Lock poisoned: dex_owner_id"))? {
            return Ok(id);
        }
        let mut rng = rand::thread_rng();
        let mut id: u64 = rng.next_u64();
        if id == 0 { id = 1; }
        {
            *self.dex_owner_id.write()
                .map_err(|_| anyhow!("Lock poisoned: dex_owner_id"))? = Some(id);
        }
        // Persist immediately
        self.save_to_disk().await?;
        Ok(id)
    }

    /// Read the last chain nullifier scan height
    pub async fn get_chain_nf_last_height(&self) -> u64 {
        self.last_chain_nf_height.read()
            .map(|guard| *guard)
            .unwrap_or(0)
    }

    /// Set and persist the last chain nullifier scan height
    pub async fn set_chain_nf_last_height(&self, height: u64) -> Result<()> {
        {
            *self.last_chain_nf_height.write()
                .map_err(|_| anyhow!("Lock poisoned: last_chain_nf_height"))? = height;
        }
        self.save_to_disk().await
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
            let mut notes = self.note_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: note_cache"))?;
            notes.insert(commitment, note);
        }

        // Save to disk
        self.save_to_disk().await?;

        Ok(())
    }

    /// Get a note by commitment
    pub async fn get_note(&self, commitment: &[u8; NOTE_COMMITMENT_SIZE]) -> Option<EncryptedNote> {
        self.note_cache.read().ok()?.get(commitment).cloned()
    }

    /// List all notes
    pub async fn list_notes(&self) -> Vec<EncryptedNote> {
        self.note_cache.read()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_else(|_| Vec::new())
    }

    /// List unspent notes
    pub async fn list_unspent_notes(&self) -> Vec<EncryptedNote> {
        self.note_cache
            .read()
            .map(|guard| guard.values().filter(|note| !note.is_spent).cloned().collect())
            .unwrap_or_else(|_| Vec::new())
    }

    /// Update note spent status
    pub async fn update_note_spent_status(
        &self,
        commitment: &[u8; NOTE_COMMITMENT_SIZE],
        is_spent: bool,
    ) -> Result<()> {
        {
            let mut notes = self.note_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: note_cache"))?;
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
            *self.pcd_state_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: pcd_state_cache"))? = Some(pcd_state);
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Get current PCD state
    pub async fn get_pcd_state(&self) -> Option<PcdStateRecord> {
        self.pcd_state_cache.read().ok()?.clone()
    }

    /// Add or update witness
    pub async fn upsert_witness(&self, position: u64, witness: WitnessRecord) -> Result<()> {
        {
            let mut witnesses = self.witness_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: witness_cache"))?;
            witnesses.insert(position, witness);
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Get witness by position
    pub async fn get_witness(&self, position: u64) -> Option<WitnessRecord> {
        self.witness_cache.read().ok()?.get(&position).cloned()
    }

    /// Get all witnesses
    pub async fn list_witnesses(&self) -> Vec<WitnessRecord> {
        self.witness_cache
            .read()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_else(|_| Vec::new())
    }

    /// Delete a note (for spent notes cleanup)
    pub async fn delete_note(&self, commitment: &[u8; NOTE_COMMITMENT_SIZE]) -> Result<()> {
        {
            let mut notes = self.note_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: note_cache"))?;
            notes.remove(commitment);
        }

        self.save_to_disk().await?;

        Ok(())
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> DatabaseStats {
        let (total_notes, unspent_notes, spent_notes) = self.note_cache.read()
            .map(|notes| {
                let unspent = notes.values().filter(|note| !note.is_spent).count();
                let total = notes.len();
                (total, unspent, total - unspent)
            })
            .unwrap_or((0, 0, 0));

        let has_pcd_state = self.pcd_state_cache.read()
            .map(|guard| guard.is_some())
            .unwrap_or(false);
        
        let witness_count = self.witness_cache.read()
            .map(|guard| guard.len())
            .unwrap_or(0);

        DatabaseStats {
            total_notes,
            unspent_notes,
            spent_notes,
            has_pcd_state,
            witness_count,
        }
    }

    /// Get persisted OOB keypair, if any
    pub async fn get_oob_keypair(&self) -> Result<Option<(KyberPublicKey, KyberSecretKey)>> {
        if let Some(keys) = self.oob_keys_cache.read()
            .map_err(|_| anyhow!("Lock poisoned: oob_keys_cache"))?
            .as_ref() {
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
            *self.oob_keys_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: oob_keys_cache"))? = Some(keys);
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
        if let Some(rec) = self.spend_secret_cache.read()
            .map_err(|_| anyhow!("Lock poisoned: spend_secret_cache"))?
            .as_ref() {
            return rec.decrypt(&self.master_key);
        }
        // Generate new random spend secret
        let mut sec = [0u8; 32];
        OsRng.fill_bytes(&mut sec);
        let rec = SpendSecretRecord::new(&sec, &self.master_key)?;
        {
            *self.spend_secret_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: spend_secret_cache"))? = Some(rec);
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

/// Persisted Zcash seed mnemonic (BIP-39) encrypted at rest, with birthday height
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZcashSeedRecord {
    /// Encrypted mnemonic phrase bytes (UTF-8), nonce + ciphertext
    pub encrypted_mnemonic: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Birthday height for light client scanning optimization
    pub birthday_height: u64,
}

impl ZcashSeedRecord {
    /// Create a new encrypted Zcash seed record
    pub fn new(mnemonic: &str, birthday_height: u64, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<Self> {
        let nonce = SimpleAead::generate_nonce();
        let encrypted_mnemonic = SimpleAead::encrypt(master_key, &nonce, mnemonic.as_bytes(), b"zcash_seed")?;
        Ok(Self { encrypted_mnemonic, nonce, birthday_height })
    }

    /// Decrypt the mnemonic phrase
    pub fn decrypt_mnemonic(&self, master_key: &[u8; DB_MASTER_KEY_SIZE]) -> Result<String> {
        if self.encrypted_mnemonic.len() < AES_NONCE_SIZE { return Err(anyhow!("Ciphertext too short")); }
        if self.encrypted_mnemonic[..AES_NONCE_SIZE] != self.nonce { return Err(anyhow!("Nonce mismatch for ZcashSeedRecord")); }
        let bytes = SimpleAead::decrypt(master_key, &self.encrypted_mnemonic, b"zcash_seed")?;
        String::from_utf8(bytes).map_err(|_| anyhow!("Decrypted mnemonic not valid UTF-8"))
    }
}

impl Drop for WalletDatabase {
    fn drop(&mut self) {
        // Best-effort unlock; dropping the file will also release the lock
        let _ = fs2::FileExt::unlock(&self.lock_file);
    }
}

/// Legacy fixed-token balances file format (for migration only)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct TokenBalancesLegacy {
    pub usdc: u64,
    pub base: u64,
    pub usdc_locked: u64,
    pub base_locked: u64,
}

pub const TOKEN_USDC: &str = "USDC";
pub const TOKEN_BASE: &str = "BASE";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TokenMeta { pub decimals: u8 }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct BalanceRecord { pub available: u64, pub locked: u64 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenLedger {
    balances: HashMap<String, BalanceRecord>,
    meta: HashMap<String, TokenMeta>,
}

impl TokenLedger {
    fn set_meta(&mut self, token: String, meta: TokenMeta) { self.meta.insert(token, meta); }
    fn ensure_token(&mut self, token: &str) {
        self.balances.entry(token.to_string()).or_default();
    }
    fn set_balance(&mut self, token: &str, available: u64, locked: u64) {
        self.balances.insert(token.to_string(), BalanceRecord { available, locked });
    }
    fn available_of(&self, token: &str) -> u64 { self.balances.get(token).map(|b| b.available).unwrap_or(0) }
    fn locked_of(&self, token: &str) -> u64 { self.balances.get(token).map(|b| b.locked).unwrap_or(0) }
    fn credit_available(&mut self, token: &str, amount: u64) {
        self.ensure_token(token);
        if let Some(e) = self.balances.get_mut(token) {
            e.available = e.available.saturating_add(amount);
        }
    }
    fn debit_available(&mut self, token: &str, amount: u64) -> Result<()> {
        self.ensure_token(token);
        let e = self.balances.get_mut(token)
            .ok_or_else(|| anyhow!("Token not found: {}", token))?;
        if e.available < amount { return Err(anyhow!("insufficient available balance for {}", token)); }
        e.available -= amount; Ok(())
    }
    fn lock(&mut self, token: &str, amount: u64) -> Result<()> {
        self.ensure_token(token);
        let e = self.balances.get_mut(token)
            .ok_or_else(|| anyhow!("Token not found: {}", token))?;
        if e.available < amount { return Err(anyhow!("insufficient available to lock for {}", token)); }
        e.available -= amount; e.locked = e.locked.saturating_add(amount); Ok(())
    }
    fn unlock(&mut self, token: &str, amount: u64) -> Result<()> {
        self.ensure_token(token);
        let e = self.balances.get_mut(token)
            .ok_or_else(|| anyhow!("Token not found: {}", token))?;
        if e.locked < amount { return Err(anyhow!("unlock exceeds locked for {}", token)); }
        e.locked -= amount; e.available = e.available.saturating_add(amount); Ok(())
    }
    fn spend_locked(&mut self, token: &str, amount: u64) -> Result<()> {
        self.ensure_token(token);
        let e = self.balances.get_mut(token)
            .ok_or_else(|| anyhow!("Token not found: {}", token))?;
        if e.locked < amount { return Err(anyhow!("spend exceeds locked for {}", token)); }
        e.locked -= amount; Ok(())
    }
}

impl WalletDatabase {
    /// Get current USDC balance
    pub async fn get_usdc_balance(&self) -> u64 { self.get_token_available(TOKEN_USDC).await }

    /// Deposit USDC into the wallet
    pub async fn deposit_usdc(&self, amount: u64) -> Result<()> { self.credit_token(TOKEN_USDC, amount).await }

    /// Withdraw USDC from the wallet
    pub async fn withdraw_usdc(&self, amount: u64) -> Result<()> { self.debit_token(TOKEN_USDC, amount).await }

    /// Get base asset balance
    pub async fn get_base_balance(&self) -> u64 { self.get_token_available(TOKEN_BASE).await }

    /// Deposit base asset units (for selling). For demo/testing.
    pub async fn deposit_base(&self, amount: u64) -> Result<()> { self.credit_token(TOKEN_BASE, amount).await }

    /// Withdraw base asset units (for settlement)
    pub async fn withdraw_base(&self, amount: u64) -> Result<()> { self.debit_token(TOKEN_BASE, amount).await }

    /// Get locked USDC
    pub async fn get_locked_usdc(&self) -> u64 { self.get_token_locked(TOKEN_USDC).await }

    /// Get locked base
    pub async fn get_locked_base(&self) -> u64 { self.get_token_locked(TOKEN_BASE).await }

    /// Lock USDC for open orders
    pub async fn lock_usdc(&self, amount: u64) -> Result<()> { self.lock_token(TOKEN_USDC, amount).await }

    /// Unlock USDC back to available
    pub async fn unlock_usdc(&self, amount: u64) -> Result<()> { self.unlock_token(TOKEN_USDC, amount).await }

    /// Spend locked USDC (filled amount)
    pub async fn spend_locked_usdc(&self, amount: u64) -> Result<()> { self.spend_locked_token(TOKEN_USDC, amount).await }

    /// Lock base for open sell orders
    pub async fn lock_base(&self, amount: u64) -> Result<()> { self.lock_token(TOKEN_BASE, amount).await }

    /// Unlock base back to available
    pub async fn unlock_base(&self, amount: u64) -> Result<()> { self.unlock_token(TOKEN_BASE, amount).await }

    /// Spend locked base (filled amount)
    pub async fn spend_locked_base(&self, amount: u64) -> Result<()> { self.spend_locked_token(TOKEN_BASE, amount).await }

    /// Atomic settlement for a bid fill: spend locked USDC and credit base.
    pub async fn settle_bid_fill(&self, base_qty: u64, quote_cost: u64) -> Result<()> {
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.spend_locked(TOKEN_USDC, quote_cost)?;
            ledger.credit_available(TOKEN_BASE, base_qty);
        }
        self.save_to_disk().await
    }

    /// Atomic settlement for an ask fill: spend locked base and credit USDC.
    pub async fn settle_ask_fill(&self, base_qty: u64, quote_gain: u64) -> Result<()> {
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.spend_locked(TOKEN_BASE, base_qty)?;
            ledger.credit_available(TOKEN_USDC, quote_gain);
        }
        self.save_to_disk().await
    }

    /// Generic helpers
    pub async fn credit_token(&self, token: &str, amount: u64) -> Result<()> {
        if amount == 0 { return Ok(()); }
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.credit_available(token, amount);
        }
        self.save_to_disk().await
    }

    pub async fn debit_token(&self, token: &str, amount: u64) -> Result<()> {
        if amount == 0 { return Ok(()); }
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.debit_available(token, amount)?;
        }
        self.save_to_disk().await
    }

    pub async fn lock_token(&self, token: &str, amount: u64) -> Result<()> {
        if amount == 0 { return Ok(()); }
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.lock(token, amount)?;
        }
        self.save_to_disk().await
    }

    pub async fn unlock_token(&self, token: &str, amount: u64) -> Result<()> {
        if amount == 0 { return Ok(()); }
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.unlock(token, amount)?;
        }
        self.save_to_disk().await
    }

    pub async fn spend_locked_token(&self, token: &str, amount: u64) -> Result<()> {
        if amount == 0 { return Ok(()); }
        {
            let mut ledger = self.token_ledger.write()
                .map_err(|_| anyhow!("Lock poisoned: token_ledger"))?;
            ledger.spend_locked(token, amount)?;
        }
        self.save_to_disk().await
    }

    pub async fn get_token_available(&self, token: &str) -> u64 {
        self.token_ledger.read()
            .map(|guard| guard.available_of(token))
            .unwrap_or(0)
    }

    pub async fn get_token_locked(&self, token: &str) -> u64 {
        self.token_ledger.read()
            .map(|guard| guard.locked_of(token))
            .unwrap_or(0)
    }

    /// Persist Zcash mnemonic and birthday height (encrypted at rest)
    pub async fn set_zcash_seed(&self, mnemonic: &str, birthday_height: u64) -> Result<()> {
        let rec = ZcashSeedRecord::new(mnemonic, birthday_height, &self.master_key)?;
        {
            *self.zcash_seed_cache.write()
                .map_err(|_| anyhow!("Lock poisoned: zcash_seed_cache"))? = Some(rec);
        }
        self.save_to_disk().await
    }

    /// Retrieve Zcash mnemonic and birthday height if present
    pub async fn get_zcash_seed(&self) -> Option<(String, u64)> {
        let rec_opt = {
            self.zcash_seed_cache.read().ok()?.clone()
        };
        if let Some(rec) = rec_opt {
            if let Ok(m) = rec.decrypt_mnemonic(&self.master_key) {
                return Some((m, rec.birthday_height));
            }
        }
        None
    }

    /// Check if a Zcash seed is stored
    pub async fn has_zcash_seed(&self) -> bool {
        self.zcash_seed_cache.read()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
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
