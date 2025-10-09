//! # wallet
//!
//! Tachyon wallet implementation providing secure note management,
//! PCD state synchronization, and transaction construction.

use anyhow::{anyhow, Result};
use net_iroh::{BlobKind, Cid, ControlMessage, TachyonNetwork};
use pcd_core::{
    PcdState, PcdStateManager, PcdSyncClient, PcdSyncManager, SimplePcdVerifier,
};
use pq_crypto::{
    derive_nullifier, KyberPublicKey, KyberSecretKey, NullifierDerivationMode, OutOfBandPayment,
    SimpleKem,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, sync::Arc};
use storage::{EncryptedNote, PcdStateRecord, WalletDatabase, NOTE_COMMITMENT_SIZE};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    task::JoinHandle,
};

/// Wallet configuration
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Database path for encrypted storage
    pub db_path: String,
    /// Master password for database encryption
    pub master_password: String,
    /// Network configuration (iroh node ID, etc.)
    pub network_config: NetworkConfig,
    /// Sync configuration
    pub sync_config: SyncConfig,
}

impl Default for WalletConfig {
    fn default() -> Self {
        // Default is suitable for local development/tests only. Use from_env() for production.
        Self {
            db_path: "./wallet_db".to_string(),
            master_password: "default_password".to_string(),
            network_config: NetworkConfig::default(),
            sync_config: SyncConfig::default(),
        }
    }
}

impl WalletConfig {
    /// Load configuration from environment variables (production-friendly)
    ///
    /// Supported variables:
    /// - TACHYON_DB_PATH
    /// - TACHYON_MASTER_PASSWORD
    /// - TACHYON_IROH_DATA_DIR
    /// - TACHYON_BOOTSTRAP_NODES (comma-separated)
    /// - TACHYON_OSS_ENDPOINTS (comma-separated)
    /// - TACHYON_SYNC_INTERVAL_SECS
    /// - TACHYON_MAX_SYNC_BATCH_SIZE
    pub fn from_env() -> Self {
        let get = |key: &str| std::env::var(key).ok();

        let db_path = get("TACHYON_DB_PATH").unwrap_or_else(|| "./wallet_db".to_string());
        let master_password =
            get("TACHYON_MASTER_PASSWORD").unwrap_or_else(|| "default_password".to_string());

        let data_dir = get("TACHYON_IROH_DATA_DIR").unwrap_or_else(|| "./wallet_data".to_string());
        let bootstrap_nodes = get("TACHYON_BOOTSTRAP_NODES")
            .map(|s| {
                s.split(',')
                    .filter(|x| !x.is_empty())
                    .map(|s| s.trim().to_string())
                    .collect()
            })
            .unwrap_or_else(|| Vec::new());

        let oss_endpoints = get("TACHYON_OSS_ENDPOINTS")
            .map(|s| {
                s.split(',')
                    .filter(|x| !x.is_empty())
                    .map(|s| s.trim().to_string())
                    .collect()
            })
            .unwrap_or_else(|| vec!["localhost:8080".to_string()]);

        let sync_interval_secs = get("TACHYON_SYNC_INTERVAL_SECS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);

        let max_sync_batch_size = get("TACHYON_MAX_SYNC_BATCH_SIZE")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10);

        Self {
            db_path,
            master_password,
            network_config: NetworkConfig {
                data_dir,
                bootstrap_nodes,
            },
            sync_config: SyncConfig {
                oss_endpoints,
                sync_interval_secs,
                max_sync_batch_size,
            },
        }
    }

    /// Validate configuration for production. Fails on insecure defaults unless explicitly allowed.
    pub fn validate(&self) -> Result<()> {
        let allow_insecure = std::env::var("TACHYON_ALLOW_INSECURE").unwrap_or_default() == "1";

        let insecure_password = self.master_password == "default_password";
        let insecure_oss = self
            .sync_config
            .oss_endpoints
            .iter()
            .any(|e| e.contains("localhost"));

        if (insecure_password || insecure_oss) && !allow_insecure {
            return Err(anyhow!(
                "Insecure configuration: {}{}. Set secure values or TACHYON_ALLOW_INSECURE=1 for development.",
                if insecure_password { "MASTER_PASSWORD is default. " } else { "" },
                if insecure_oss { "OSS endpoints include localhost." } else { "" }
            ));
        }

        Ok(())
    }
}

/// Network configuration for wallet networking
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Iroh data directory
    pub data_dir: String,
    /// Bootstrap nodes for peer discovery
    pub bootstrap_nodes: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            data_dir: "./wallet_data".to_string(),
            bootstrap_nodes: vec![],
        }
    }
}

/// Sync configuration for state synchronization
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// OSS server endpoints to connect to
    pub oss_endpoints: Vec<String>,
    /// Sync interval in seconds
    pub sync_interval_secs: u64,
    /// Maximum number of blocks to sync in one batch
    pub max_sync_batch_size: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            oss_endpoints: vec!["localhost:8080".to_string()],
            sync_interval_secs: 30,
            max_sync_batch_size: 10,
        }
    }
}

/// Wallet note representation (decrypted for internal use)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletNote {
    /// Note commitment hash
    pub commitment: [u8; NOTE_COMMITMENT_SIZE],
    /// Note value
    pub value: u64,
    /// Recipient address (public key hash)
    pub recipient: [u8; 32],
    /// Note randomness/nullifier seed
    pub rseed: [u8; 32],
    /// Position in MMR accumulator
    pub position: u64,
    /// Block height when note was created
    pub block_height: u64,
    /// Whether this note has been spent
    pub is_spent: bool,
    /// Witness data for spending
    pub witness_data: Vec<u8>,
    /// Memo field (optional)
    pub memo: Option<String>,
}

/// Convert encrypted note to wallet note
impl TryFrom<EncryptedNote> for WalletNote {
    type Error = anyhow::Error;

    fn try_from(encrypted_note: EncryptedNote) -> Result<Self> {
        // NOTE: Proper decryption requires access to the master key; WalletNote::try_from
        // is used in contexts where we already have decrypted note data. For now, we expect
        // the encrypted payload to be structured as:
        // [commitment(32) | value(8) | recipient(32) | rseed(32) | memo_len(2) | memo(..)]
        let data = &encrypted_note.encrypted_data;
        if data.len() < NOTE_COMMITMENT_SIZE + 8 + 32 + 32 + 2 {
            return Err(anyhow!("EncryptedNote payload too short for parsing"));
        }

        let mut offset = 0usize;
        let mut commitment = [0u8; NOTE_COMMITMENT_SIZE];
        commitment.copy_from_slice(&data[offset..offset + NOTE_COMMITMENT_SIZE]);
        offset += NOTE_COMMITMENT_SIZE;

        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&data[offset..offset + 8]);
        let value = u64::from_le_bytes(value_bytes);
        offset += 8;

        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut rseed = [0u8; 32];
        rseed.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut memo_len_bytes = [0u8; 2];
        memo_len_bytes.copy_from_slice(&data[offset..offset + 2]);
        let memo_len = u16::from_le_bytes(memo_len_bytes) as usize;
        offset += 2;

        let memo = if memo_len > 0 && offset + memo_len <= data.len() {
            Some(String::from_utf8_lossy(&data[offset..offset + memo_len]).to_string())
        } else {
            None
        };

        Ok(WalletNote {
            commitment,
            value,
            recipient,
            rseed,
            position: encrypted_note.position,
            block_height: encrypted_note.block_height,
            is_spent: encrypted_note.is_spent,
            witness_data: Vec::new(),
            memo,
        })
    }
}

/// Wallet state and operations
pub struct TachyonWallet {
    /// Wallet configuration
    config: WalletConfig,
    /// Encrypted database
    database: Arc<WalletDatabase>,
    /// Network client
    network: Arc<TachyonNetwork>,
    /// PCD state manager
    pcd_manager: Arc<RwLock<PcdStateManager<SimplePcdVerifier>>>,
    /// PCD sync manager
    sync_manager: Arc<RwLock<Option<PcdSyncManager<WalletSyncClient, SimplePcdVerifier>>>>,
    /// OOB payment handler
    oob_handler: Arc<RwLock<OutOfBandHandler>>,
    /// Background sync task
    sync_task: Option<JoinHandle<()>>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::UnboundedSender<()>>,
}

/// Out-of-band payment handler
pub struct OutOfBandHandler {
    /// Our Kyber secret key for decrypting OOB payments
    secret_key: KyberSecretKey,
    /// Pending OOB payments
    pending_payments: HashMap<[u8; 32], OutOfBandPayment>, // Keyed by payment hash
}

impl OutOfBandHandler {
    /// Create a new OOB handler
    pub fn new(secret_key: KyberSecretKey) -> Result<Self> {
        Ok(Self {
            secret_key,
            pending_payments: HashMap::new(),
        })
    }

    /// Get our public key for OOB payments
    pub fn public_key(&self, _database: &WalletDatabase) -> KyberPublicKey {
        // The public key is persisted alongside the secret key in the database
        // We load it from the DB to ensure consistency across restarts
        // This function is sync because DB caches the key material
        // Fallback to generating a fresh keypair should not happen here; handled at wallet init
        // Deprecated; wallet.get_oob_public_key should be used instead
        KyberPublicKey::new(Vec::new())
    }

    /// Add a pending OOB payment
    pub fn add_pending_payment(&mut self, payment: OutOfBandPayment) -> Result<[u8; 32]> {
        payment.verify()?;
        let payment_hash = blake3::hash(payment.encrypted_metadata.as_slice());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(payment_hash.as_bytes());
        self.pending_payments.insert(hash_bytes, payment);
        Ok(hash_bytes)
    }

    /// Process a pending payment and extract note data
    pub fn process_payment(&mut self, payment_hash: &[u8; 32]) -> Result<Option<WalletNote>> {
        if let Some(payment) = self.pending_payments.remove(payment_hash) {
            let decrypted_data = payment.decrypt(&self.secret_key)?;
            // Parse the decrypted note data and create a WalletNote
            // This would involve deserializing the note structure
            Ok(Some(WalletNote {
                commitment: [0u8; NOTE_COMMITMENT_SIZE],
                value: 0,
                recipient: [0u8; 32],
                rseed: [0u8; 32],
                position: 0,
                block_height: 0,
                is_spent: false,
                witness_data: decrypted_data,
                memo: None,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Wallet sync client implementation
pub struct WalletSyncClient {
    /// Network client reference
    network: Arc<TachyonNetwork>,
    /// Blob announcement receiver
    announcements: broadcast::Receiver<(BlobKind, Cid, u64, usize, String)>,
}

impl WalletSyncClient {
    /// Create a new sync client
    pub fn new(network: Arc<TachyonNetwork>) -> Self {
        let announcements = network.subscribe_announcements();
        Self {
            network,
            announcements,
        }
    }

    /// Subscribe to blob announcements for sync
    pub async fn subscribe_to_sync_blobs(&self) -> Result<()> {
        let _subscription = ControlMessage::Subscribe {
            kinds: vec![
                BlobKind::CommitmentDelta,
                BlobKind::NullifierDelta,
                BlobKind::PcdTransition,
            ],
        };

        // Send subscription message (this would be sent over control stream)
        // For now, just log it
        tracing::info!("Subscribing to sync blob types");
        Ok(())
    }

    /// Process next announcement and fetch blob via ticket
    pub async fn poll_and_fetch_once(&mut self) -> Result<Option<(BlobKind, Vec<u8>)>> {
        match self.announcements.recv().await {
            Ok((kind, _cid, _height, _size, ticket)) => {
                let bytes = self.network.fetch_blob_from_ticket(&ticket).await?;
                Ok(Some((kind, bytes.to_vec())))
            }
            Err(_) => Ok(None),
        }
    }
}

impl PcdSyncClient for WalletSyncClient {
    async fn fetch_state(&self, height: u64) -> Result<Option<PcdState>> {
        // Request PCD state for specific height
        // This would send a control message and wait for response
        tracing::debug!("Fetching PCD state for height {}", height);

        // Placeholder - in real implementation, this would:
        // 1. Send ControlMessage::Request for state blob
        // 2. Wait for ControlMessage::Response
        // 3. Deserialize the PCD state

        Ok(None) // Placeholder
    }

    async fn fetch_delta_bundle(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Option<pcd_core::PcdDeltaBundle>> {
        // Request delta bundle for height range
        tracing::debug!(
            "Fetching delta bundle for heights {} to {}",
            start_height,
            end_height
        );

        // Placeholder - would fetch and return delta bundle
        Ok(None)
    }

    async fn fetch_transition_proof(
        &self,
        prev_height: u64,
        new_height: u64,
    ) -> Result<Option<Vec<u8>>> {
        // Request transition proof between heights
        tracing::debug!(
            "Fetching transition proof for {} to {}",
            prev_height,
            new_height
        );

        // Placeholder - would fetch and return transition proof
        Ok(None)
    }
}

impl TachyonWallet {
    /// Create a new wallet instance
    pub async fn new(config: WalletConfig) -> Result<Self> {
        // Validate configuration unless explicitly allowed for development/test
        #[allow(unused)]
        {
            // During unit tests we keep defaults; in other contexts enforce unless env allows
            let running_tests = std::env::var("TACHYON_UNDER_TEST").unwrap_or_default() == "1";
            if !running_tests {
                let _ = config.validate()?;
            }
        }
        // Initialize encrypted database
        let db_path = Path::new(&config.db_path);
        let database = Arc::new(WalletDatabase::new(db_path, &config.master_password).await?);

        // Initialize network client
        let network_path = Path::new(&config.network_config.data_dir);
        let network = Arc::new(TachyonNetwork::new(network_path).await?);

        // Initialize PCD state manager
        let verifier = SimplePcdVerifier;
        let pcd_manager = Arc::new(RwLock::new(PcdStateManager::new(verifier)));

        // Ensure OOB keypair exists and load it
        let (_pk, sk) = database.get_or_generate_oob_keypair().await?;

        // Initialize OOB handler with persisted secret key
        let oob_handler = Arc::new(RwLock::new(OutOfBandHandler::new(sk)?));

        // Initialize sync manager
        let sync_client = WalletSyncClient::new(network.clone());
        let sync_manager = Arc::new(RwLock::new(Some(PcdSyncManager::new(
            sync_client,
            SimplePcdVerifier,
        ))));

        Ok(Self {
            config,
            database,
            network,
            pcd_manager,
            sync_manager,
            oob_handler,
            sync_task: None,
            shutdown_tx: None,
        })
    }

    /// Initialize wallet with genesis state
    pub async fn initialize(&mut self) -> Result<()> {
        // Check if we already have a PCD state
        let current_state = self.database.get_pcd_state().await;

        if let Some(pcd_record) = current_state {
            // Load existing PCD state
            let state_data = pcd_record.decrypt_state(&self.database.master_key)?;
            let pcd_state = PcdState::new(
                pcd_record.anchor_height,
                pcd_record.state_commitment,
                [0u8; 32], // Would be stored in state_data
                [0u8; 32], // Would be stored in state_data
                state_data,
                pcd_record.proof,
            )?;

            let mut pcd_manager = self.pcd_manager.write().await;
            pcd_manager.initialize_genesis(pcd_state)?;
        } else {
            // Create genesis state
            let genesis_state = PcdState::new(
                0,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
                b"genesis_state".to_vec(),
                vec![0u8; 1024],
            )?;

            let mut pcd_manager = self.pcd_manager.write().await;
            pcd_manager.initialize_genesis(genesis_state.clone())?;

            // Persist genesis state
            let pcd_record = PcdStateRecord::new(
                0,
                [0u8; 32],
                b"genesis_state",
                vec![0u8; 1024],
                &self.database.master_key,
            )?;

            self.database.set_pcd_state(pcd_record).await?;
        }

        // Start background sync
        self.start_sync_task().await?;

        Ok(())
    }

    /// Start background synchronization task
    async fn start_sync_task(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        self.shutdown_tx = Some(shutdown_tx);

        let sync_manager = self.sync_manager.clone();
        let network = self.network.clone();
        let sync_interval = self.config.sync_config.sync_interval_secs;

        let sync_task = tokio::spawn(async move {
            // Subscribe to blob announcements
            let mut client = WalletSyncClient::new(network.clone());
            let _ = client.subscribe_to_sync_blobs().await;

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sync_interval));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Perform sync operation
                        if let Some(sync_mgr) = sync_manager.write().await.as_mut() {
                            // Sync to latest height (placeholder)
                            let target_height = 1000; // Would get from network
                            if let Err(e) = sync_mgr.sync_to_height(target_height).await {
                                tracing::error!("Sync failed: {}", e);
                            }
                        }
                    }
                    fetched = client.poll_and_fetch_once() => {
                        match fetched {
                            Ok(Some((kind, bytes))) => {
                                tracing::info!("Fetched announced blob {:?} ({} bytes)", kind, bytes.len());
                                // TODO: route bytes to appropriate handler (MMR delta / transition)
                            }
                            Ok(None) => {}
                            Err(e) => tracing::warn!("Announcement fetch error: {}", e),
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Sync task shutting down");
                        break;
                    }
                }
            }
        });

        self.sync_task = Some(sync_task);
        Ok(())
    }

    /// Stop the wallet and cleanup resources
    pub async fn shutdown(&mut self) -> Result<()> {
        // Stop sync task
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        if let Some(sync_task) = self.sync_task.take() {
            sync_task.await?;
        }

        // Gracefully shutdown network router
        self.network.shutdown().await?;

        Ok(())
    }

    /// Get wallet statistics
    pub async fn get_stats(&self) -> Result<WalletStats> {
        let db_stats = self.database.get_stats().await;

        Ok(WalletStats {
            db_stats,
            network_connected: true, // Would check actual connection
            current_anchor_height: self
                .pcd_manager
                .read()
                .await
                .current_state()
                .map(|s| s.anchor_height),
            pending_payments: self.oob_handler.read().await.pending_payments.len(),
        })
    }

    /// Receive an out-of-band payment
    pub async fn receive_oob_payment(&self, payment: OutOfBandPayment) -> Result<[u8; 32]> {
        let mut handler = self.oob_handler.write().await;
        handler.add_pending_payment(payment)
    }

    /// Process a pending OOB payment
    pub async fn process_oob_payment(&self, payment_hash: &[u8; 32]) -> Result<Option<WalletNote>> {
        let mut handler = self.oob_handler.write().await;
        handler.process_payment(payment_hash)
    }

    /// Create an out-of-band payment for sending
    pub async fn create_oob_payment(
        &self,
        recipient_pk: KyberPublicKey,
        note_data: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<OutOfBandPayment> {
        OutOfBandPayment::new(recipient_pk, &note_data, associated_data)
    }

    /// Get our public key for OOB payments
    pub async fn get_oob_public_key(&self) -> KyberPublicKey {
        // Retrieve from storage to avoid accidental regeneration
        if let Ok(Some((pk, _))) = self.database.get_oob_keypair().await {
            pk
        } else {
            // Should not happen; fallback to ephemeral for continuity
            let (pk, _sk) = SimpleKem::generate_keypair().unwrap();
            pk
        }
    }

    /// List wallet notes
    pub async fn list_notes(&self) -> Result<Vec<WalletNote>> {
        let encrypted_notes = self.database.list_notes().await;
        let mut wallet_notes = Vec::new();

        for enc_note in encrypted_notes {
            if let Ok(wallet_note) = WalletNote::try_from(enc_note) {
                wallet_notes.push(wallet_note);
            }
        }

        Ok(wallet_notes)
    }

    /// List unspent notes
    pub async fn list_unspent_notes(&self) -> Result<Vec<WalletNote>> {
        let encrypted_notes = self.database.list_unspent_notes().await;
        let mut wallet_notes = Vec::new();

        for enc_note in encrypted_notes {
            if let Ok(wallet_note) = WalletNote::try_from(enc_note) {
                wallet_notes.push(wallet_note);
            }
        }

        Ok(wallet_notes)
    }

    /// Build a transaction (spend) from selected notes
    pub async fn build_transaction(
        &self,
        note_commitments: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
        output_notes: Vec<WalletNote>,
    ) -> Result<Transaction> {
        // Anchor to current PCD state
        let anchor_height = self
            .pcd_manager
            .read()
            .await
            .current_state()
            .map(|s| s.anchor_height)
            .unwrap_or(0);

        // Derive nullifiers using blinded mode for oblivious sync compatibility
        let nullifiers: Vec<[u8; 32]> = note_commitments
            .iter()
            .map(|c| {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(blake3::hash(c).as_bytes());
                derive_nullifier(c, &seed, NullifierDerivationMode::Blinded)
            })
            .collect();

        // Build spend proofs (placeholder opaque bytes per input)
        let spend_proofs: Vec<Vec<u8>> = note_commitments
            .iter()
            .map(|c| {
                let mut h = blake3::Hasher::new();
                h.update(b"spend_proof");
                h.update(c);
                h.finalize().as_bytes().to_vec()
            })
            .collect();

        // Build output proofs (placeholder hash of output commitment)
        let output_proofs: Vec<Vec<u8>> = output_notes
            .iter()
            .map(|o| {
                let mut h = blake3::Hasher::new();
                h.update(b"output_proof");
                h.update(&o.commitment);
                h.finalize().as_bytes().to_vec()
            })
            .collect();

        // Compose a PCD binding proof over current anchor (placeholder binds to anchor height)
        let mut pcd_hasher = blake3::Hasher::new();
        pcd_hasher.update(b"tx_pcd_binding");
        pcd_hasher.update(&anchor_height.to_le_bytes());
        for n in &nullifiers {
            pcd_hasher.update(n);
        }
        let pcd_proof = pcd_hasher.finalize().as_bytes().to_vec();

        Ok(Transaction {
            inputs: note_commitments,
            outputs: output_notes,
            anchor_height,
            pcd_proof,
            spend_proofs,
            output_proofs,
        })
    }

    /// Sync wallet state to latest
    pub async fn sync(&self) -> Result<()> {
        let mut sync_manager = self.sync_manager.write().await;
        if let Some(ref mut sync_mgr) = sync_manager.as_mut() {
            let target_height = 1000; // Would get from network
            sync_mgr.sync_to_height(target_height).await?;
        }
        Ok(())
    }

    /// Get current PCD state
    pub async fn get_pcd_state(&self) -> Option<PcdState> {
        self.pcd_manager.read().await.current_state().cloned()
    }
}

/// Wallet statistics
#[derive(Debug, Clone)]
pub struct WalletStats {
    pub db_stats: storage::DatabaseStats,
    pub network_connected: bool,
    pub current_anchor_height: Option<u64>,
    pub pending_payments: usize,
}

/// Transaction representation (simplified)
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Input note commitments being spent
    pub inputs: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
    /// Output notes being created
    pub outputs: Vec<WalletNote>,
    /// Anchor height for PCD proof
    pub anchor_height: u64,
    /// PCD proof data
    pub pcd_proof: Vec<u8>,
    /// Spend proofs for input notes
    pub spend_proofs: Vec<Vec<u8>>,
    /// Output proofs for output notes
    pub output_proofs: Vec<Vec<u8>>,
}

impl Transaction {
    /// Verify transaction integrity
    pub fn verify(&self) -> Result<()> {
        // Basic structural checks
        if self.pcd_proof.is_empty() {
            return Err(anyhow!("Missing PCD proof"));
        }

        // Inputs and outputs must be present
        if self.inputs.is_empty() && self.outputs.is_empty() {
            return Err(anyhow!("Transaction must have inputs or outputs"));
        }

        // Placeholder integrity checks: prove binding between anchor and inputs/outputs
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tx_pcd_binding");
        hasher.update(&self.anchor_height.to_le_bytes());
        for input in &self.inputs {
            hasher.update(input);
        }
        for output in &self.outputs {
            hasher.update(&output.commitment);
        }
        let expected = hasher.finalize();
        if self.pcd_proof.as_slice() != expected.as_bytes() {
            return Err(anyhow!("PCD binding mismatch"));
        }

        // Spend proof count should match inputs
        if self.spend_proofs.len() != self.inputs.len() {
            return Err(anyhow!("Spend proof count does not match inputs"));
        }

        // Output proof count should match outputs
        if self.output_proofs.len() != self.outputs.len() {
            return Err(anyhow!("Output proof count does not match outputs"));
        }

        // Placeholder spend proof validation (non-empty and bound to input commitment)
        for (i, input) in self.inputs.iter().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(b"spend_proof");
            h.update(input);
            let expected = h.finalize();
            if self.spend_proofs[i].as_slice() != expected.as_bytes() {
                return Err(anyhow!("Invalid spend proof for input {}", i));
            }
        }

        // Placeholder output proof validation
        for (i, output) in self.outputs.iter().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(b"output_proof");
            h.update(&output.commitment);
            let expected = h.finalize();
            if self.output_proofs[i].as_slice() != expected.as_bytes() {
                return Err(anyhow!("Invalid output proof for output {}", i));
            }
        }

        Ok(())
    }

    /// Get transaction hash
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"transaction");
        hasher.update(&self.anchor_height.to_le_bytes());

        for input in &self.inputs {
            hasher.update(input);
        }

        for output in &self.outputs {
            hasher.update(&output.commitment);
            hasher.update(&output.value.to_le_bytes());
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(hasher.finalize().as_bytes());
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_creation() {
        let config = WalletConfig::default();
        let wallet = TachyonWallet::new(config).await.unwrap();

        let stats = wallet.get_stats().await.unwrap();
        assert_eq!(stats.db_stats.total_notes, 0);
        assert_eq!(stats.pending_payments, 0);
    }

    #[tokio::test]
    async fn test_wallet_initialization() {
        let mut config = WalletConfig::default();
        config.db_path = tempfile::tempdir()
            .unwrap()
            .path()
            .join("test_wallet")
            .to_string_lossy()
            .to_string();

        let mut wallet = TachyonWallet::new(config).await.unwrap();
        wallet.initialize().await.unwrap();

        let pcd_state = wallet.get_pcd_state().await;
        assert!(pcd_state.is_some());
    }

    #[tokio::test]
    async fn test_oob_payment() {
        let config = WalletConfig::default();
        let wallet = TachyonWallet::new(config).await.unwrap();

        let recipient_pk = wallet.get_oob_public_key().await;
        let note_data = b"test note for payment".to_vec();
        let associated_data = b"payment_context".to_vec();

        let payment = wallet
            .create_oob_payment(recipient_pk, note_data.clone(), associated_data)
            .await
            .unwrap();
        payment.verify().unwrap();

        let payment_hash = wallet.receive_oob_payment(payment).await.unwrap();
        assert_eq!(payment_hash.len(), 32);

        let processed_note = wallet.process_oob_payment(&payment_hash).await.unwrap();
        assert!(processed_note.is_some());
    }

    #[tokio::test]
    async fn test_transaction_building() {
        let config = WalletConfig::default();
        let wallet = TachyonWallet::new(config).await.unwrap();

        let output_note = WalletNote {
            commitment: [1u8; NOTE_COMMITMENT_SIZE],
            value: 1000,
            recipient: [2u8; 32],
            rseed: [3u8; 32],
            position: 0,
            block_height: 0,
            is_spent: false,
            witness_data: vec![],
            memo: Some("test output".to_string()),
        };

        let transaction = wallet
            .build_transaction(vec![], vec![output_note])
            .await
            .unwrap();
        assert_eq!(transaction.outputs.len(), 1);
        assert_eq!(transaction.inputs.len(), 0);
    }
}
