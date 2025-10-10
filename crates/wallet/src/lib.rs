//! # wallet
//!
//! Tachyon wallet implementation providing secure note management,
//! PCD state synchronization, and transaction construction.

use anyhow::{anyhow, Result};
use net_iroh::{BlobKind, Cid, ControlMessage, TachyonNetwork, SyncManifest};
use pcd_core::{
    PcdState, PcdStateManager, PcdSyncClient, PcdSyncManager, SimplePcdVerifier, PcdTransition,
};
use pq_crypto::{
    derive_nf2, derive_spend_nullifier_key, KyberPublicKey, KyberSecretKey,
    OutOfBandPayment, SimpleKem,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, sync::Arc};
use storage::{EncryptedNote, PcdStateRecord, WalletDatabase, NOTE_COMMITMENT_SIZE};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    task::JoinHandle,
};
use reqwest::Client as HttpClient;
use accum_mmr::{MmrAccumulator, MmrWitness};
use bincode;

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

/// Parse a wallet note from plaintext bytes
///
/// Layout: [commitment(32) | value(8) | recipient(32) | rseed(32) | memo_len(2) | memo(..)]
fn parse_wallet_note_from_plaintext(
    data: &[u8],
    position: u64,
    block_height: u64,
    is_spent: bool,
) -> Result<WalletNote> {
    if data.len() < NOTE_COMMITMENT_SIZE + 8 + 32 + 32 + 2 {
        return Err(anyhow!("Note payload too short"));
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
        position,
        block_height,
        is_spent,
        witness_data: Vec::new(),
        memo,
    })
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
        // Deprecated; kept for compatibility. Return a placeholder is unsafe.
        // Use wallet.get_oob_public_key() instead. We still return a deterministic
        // public key derived from the secret to avoid empty key usage paths.
        // WARNING: For compatibility only; do not rely on this method in new code.
        let sk_bytes = self.secret_key.as_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oob_pk_compat");
        hasher.update(sk_bytes);
        let digest = hasher.finalize();
        KyberPublicKey::new(digest.as_bytes().to_vec())
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
            // Expected layout:
            // [commitment(32) | value(8) | recipient(32) | rseed(32) | memo_len(2) | memo(..)]
            if decrypted_data.len() < NOTE_COMMITMENT_SIZE + 8 + 32 + 32 + 2 {
                return Err(anyhow!("OOB note payload too short"));
            }

            let mut offset = 0usize;
            let mut commitment = [0u8; NOTE_COMMITMENT_SIZE];
            commitment.copy_from_slice(&decrypted_data[offset..offset + NOTE_COMMITMENT_SIZE]);
            offset += NOTE_COMMITMENT_SIZE;

            let mut vbytes = [0u8; 8];
            vbytes.copy_from_slice(&decrypted_data[offset..offset + 8]);
            let value = u64::from_le_bytes(vbytes);
            offset += 8;

            let mut recipient = [0u8; 32];
            recipient.copy_from_slice(&decrypted_data[offset..offset + 32]);
            offset += 32;

            let mut rseed = [0u8; 32];
            rseed.copy_from_slice(&decrypted_data[offset..offset + 32]);
            offset += 32;

            let mut memo_len_bytes = [0u8; 2];
            memo_len_bytes.copy_from_slice(&decrypted_data[offset..offset + 2]);
            let memo_len = u16::from_le_bytes(memo_len_bytes) as usize;
            offset += 2;
            let memo = if memo_len > 0 && offset + memo_len <= decrypted_data.len() {
                Some(String::from_utf8_lossy(&decrypted_data[offset..offset + memo_len]).to_string())
            } else { None };

            Ok(Some(WalletNote {
                commitment,
                value,
                recipient,
                rseed,
                position: 0,
                block_height: 0,
                is_spent: false,
                witness_data: Vec::new(),
                memo,
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
        Self { network, announcements }
    }

    /// Subscribe to blob announcements for sync
    pub async fn subscribe_to_sync_blobs(&self) -> Result<()> {
        let _subscription = ControlMessage::Subscribe {
            kinds: vec![
                BlobKind::CommitmentDelta,
                BlobKind::NullifierDelta,
                BlobKind::PcdTransition,
                BlobKind::Manifest,
            ],
        };
        // In a real implementation we'd send this over a control channel.
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
/// Minimal Zebra nullifier client (HTTP JSON), feature-gated by env var
struct ZebraNullifierClient {
    base_url: String,
    http: HttpClient,
}

impl ZebraNullifierClient {
    fn new(base_url: String) -> Self {
        Self { base_url, http: HttpClient::new() }
    }

    async fn fetch_nullifiers_since(&self, start_height: u64) -> Result<Vec<[u8; 32]>> {
        let url = format!("{}/nullifiers?since={}", self.base_url, start_height);
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }
        let items: Vec<String> = resp.json().await?;
        let mut out = Vec::new();
        for hex_s in items {
            if let Ok(bytes) = hex::decode(&hex_s) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    out.push(arr);
                }
            }
        }
        Ok(out)
    }
}


impl PcdSyncClient for WalletSyncClient {
    async fn fetch_state(&self, height: u64) -> Result<Option<PcdState>> {
        // Request state blob by deterministic CID from height via network index
        tracing::debug!("Fetching PCD state for height {}", height);
        // Demo path: we do not have a persisted state map yet; return None
        Ok(None)
    }

    async fn fetch_delta_bundle(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Option<pcd_core::PcdDeltaBundle>> {
        tracing::debug!(
            "Fetching delta bundle for heights {} to {}",
            start_height,
            end_height
        );
        // Prefer manifests by height to discover blob tickets without relying on nullifiers
        let anns = self.network.get_recent_announcements();
        let mut manifests: Vec<(u64, String)> = anns
            .into_iter()
            .filter(|(k, _cid, h, _s, _t)| *k == BlobKind::Manifest && *h >= start_height && *h <= end_height)
            .map(|(_k, _cid, h, _s, t)| (h, t))
            .collect();
        manifests.sort_by_key(|(h, _)| *h);

        let mut mmr_segments: Vec<Vec<u8>> = Vec::new();
        let mut nf_segments: Vec<Vec<u8>> = Vec::new();

        for (_h, ticket) in manifests {
            if let Ok(bytes) = self.network.fetch_blob_from_ticket(&ticket).await {
                if let Ok(manifest) = serde_json::from_slice::<SyncManifest>(&bytes) {
                    for item in manifest.items {
                        match item.kind {
                            BlobKind::CommitmentDelta => {
                                if let Ok(seg) = self.network.fetch_blob_from_ticket(&item.ticket).await {
                                    mmr_segments.push(seg.to_vec());
                                }
                            }
                            BlobKind::NullifierDelta => {
                                if let Ok(seg) = self.network.fetch_blob_from_ticket(&item.ticket).await {
                                    nf_segments.push(seg.to_vec());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if mmr_segments.is_empty() && nf_segments.is_empty() { return Ok(None); }
        Ok(Some(pcd_core::PcdDeltaBundle::new(mmr_segments, nf_segments, (start_height, end_height))))
    }

    async fn fetch_transition_proof(
        &self,
        prev_height: u64,
        new_height: u64,
    ) -> Result<Option<Vec<u8>>> {
        tracing::debug!("Fetching transition proof for {} to {}", prev_height, new_height);
        // Try to find a transition blob between these heights from the published cache
        let published = self.network.get_published().await;
        if let Some((_kind, bytes, _h)) = published
            .into_iter()
            .find(|(k, _b, h)| matches!(k, BlobKind::PcdTransition) && *h == new_height)
        {
            return Ok(Some(bytes));
        }
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
                [0u8; 32],
                [0u8; 32],
                state_data,
                pcd_record.proof,
            )?;

            let mut pcd_manager = self.pcd_manager.write().await;
            pcd_manager.initialize_genesis(pcd_state)?;
        } else {
            // Create genesis state with binding proof
            let anchor = 0u64;
            let mmr_root = [0u8; 32];
            let nullifier_root = [0u8; 32];
            let block_hash = [0u8; 32];
            let state_data = b"genesis_state".to_vec();

            // Compute commitment then derive proof
            let commitment = PcdState::compute_state_commitment(
                anchor,
                &mmr_root,
                &nullifier_root,
                &block_hash,
                &state_data,
            );
            let proof = {
                let mut h = blake3::Hasher::new();
                h.update(b"pcd_state_proof:v1");
                h.update(&commitment);
                h.finalize().as_bytes().to_vec()
            };
            let genesis_state = PcdState::new(anchor, mmr_root, nullifier_root, block_hash, state_data.clone(), proof.clone())?;

            let mut pcd_manager = self.pcd_manager.write().await;
            pcd_manager.initialize_genesis(genesis_state.clone())?;

            // Persist genesis state
            let pcd_record = PcdStateRecord::new(anchor, commitment, &state_data, proof, &self.database.master_key)?;

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
        let pcd_manager = self.pcd_manager.clone();
        let database = self.database.clone();

        // Optional Zebra nullifier client (chain-sourced nullifier set)
        let zebra_url_opt = std::env::var("TACHYON_ZEBRA_NULLIFIER_URL").ok();
        let zebra_client = zebra_url_opt
            .as_ref()
            .map(|u| ZebraNullifierClient::new(u.clone()));

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
                            // Sync to the latest observed height from network announcements
                            let latest_height = {
                                let published = network.get_published().await;
                                published.iter().map(|p| p.2).max().unwrap_or(0)
                            };
                            if let Err(e) = sync_mgr.sync_to_height(latest_height).await {
                                tracing::error!("Sync failed: {}", e);
                            }
                        }

                        // Chain-sourced nullifier check via Zebra if configured
                        if let Some(ref client) = zebra_client {
                            let unspent = database.list_unspent_notes().await;
                            // Derive NF2 for each unspent note and check against chain nullifiers
                            if let Ok(spend_secret) = database.get_or_generate_spend_secret().await {
                                let snk = derive_spend_nullifier_key(&spend_secret);
                                // Determine a starting height for fetching nullifiers
                                let start_h = 0u64;
                                if let Ok(chain_nfs) = client.fetch_nullifiers_since(start_h).await {
                                    let chain_set: std::collections::HashSet<[u8;32]> = chain_nfs.into_iter().collect();
                                    for enc_note in unspent {
                                        if let Ok(plaintext) = enc_note.decrypt(&database.master_key) {
                                            if let Ok(parsed) = parse_wallet_note_from_plaintext(
                                                &plaintext,
                                                enc_note.position,
                                                enc_note.block_height,
                                                enc_note.is_spent,
                                            ) {
                                                let nf2 = derive_nf2(&parsed.commitment, &parsed.rseed, &snk);
                                                if chain_set.contains(&nf2) {
                                                    let _ = database.update_note_spent_status(&parsed.commitment, true).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    fetched = client.poll_and_fetch_once() => {
                        match fetched {
                            Ok(Some((kind, bytes))) => {
                                tracing::info!("Fetched announced blob {:?} ({} bytes)", kind, bytes.len());
                                match kind {
                                    BlobKind::PcdTransition => {
                                        // Apply transition to local PCD state and persist
                                        match bincode::deserialize::<PcdTransition>(&bytes) {
                                            Ok(transition) => {
                                                let mut mgr = pcd_manager.write().await;
                                                if let Err(e) = mgr.apply_transition(transition) {
                                                    tracing::warn!("PCD transition apply failed: {}", e);
                                                } else {
                                                    // Persist current state
                                                    if let Some(state) = mgr.current_state().cloned() {
                                                        // Create a record and save
                                                        if let Ok(rec) = storage::PcdStateRecord::new(
                                                            state.anchor_height,
                                                            state.state_commitment,
                                                            &state.state_data,
                                                            state.proof.clone(),
                                                            &database.master_key,
                                                        ) {
                                                            if let Err(e) = database.set_pcd_state(rec).await {
                                                                tracing::warn!("Failed to persist PCD state: {}", e);
                                                            }
                                                        }
                                                        // Update witnesses for unspent notes against new MMR
                                                        if let Err(e) = Self::update_witnesses_after_pcd(&database, &state).await {
                                                            tracing::warn!("Witness update failed: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => tracing::warn!("Failed to decode PCD transition: {}", e),
                                        }
                                    }
                                    _ => {
                                        // Other blob kinds can be handled here (MMR/Nullifier deltas)
                                    }
                                }
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
        let note_opt = handler.process_payment(payment_hash)?;

        if let Some(note) = note_opt.clone() {
            // Reconstruct plaintext payload for storage
            let mut note_data = Vec::new();
            note_data.extend_from_slice(&note.commitment);
            note_data.extend_from_slice(&note.value.to_le_bytes());
            note_data.extend_from_slice(&note.recipient);
            note_data.extend_from_slice(&note.rseed);
            let memo_bytes = note
                .memo
                .as_deref()
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| Vec::new());
            let memo_len = (memo_bytes.len() as u16).to_le_bytes();
            note_data.extend_from_slice(&memo_len);
            note_data.extend_from_slice(&memo_bytes);

            // Encrypt and persist the note
            let enc_note = EncryptedNote::new(
                note.position,
                note.block_height,
                &note_data,
                &self.database.master_key,
            )?;
            self.database.add_note(note.commitment, enc_note).await?;
            Ok(Some(note))
        } else {
            Ok(None)
        }
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
            if let Ok(plaintext) = enc_note.decrypt(&self.database.master_key) {
                if let Ok(wallet_note) = parse_wallet_note_from_plaintext(
                    &plaintext,
                    enc_note.position,
                    enc_note.block_height,
                    enc_note.is_spent,
                ) {
                    wallet_notes.push(wallet_note);
                }
            }
        }

        Ok(wallet_notes)
    }

    /// List unspent notes
    pub async fn list_unspent_notes(&self) -> Result<Vec<WalletNote>> {
        let encrypted_notes = self.database.list_unspent_notes().await;
        let mut wallet_notes = Vec::new();

        for enc_note in encrypted_notes {
            if let Ok(plaintext) = enc_note.decrypt(&self.database.master_key) {
                if let Ok(wallet_note) = parse_wallet_note_from_plaintext(
                    &plaintext,
                    enc_note.position,
                    enc_note.block_height,
                    enc_note.is_spent,
                ) {
                    wallet_notes.push(wallet_note);
                }
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

        // Derive NF2 spend-authority nullifiers
        let spend_secret = self.database.get_or_generate_spend_secret().await?;
        let snk = derive_spend_nullifier_key(&spend_secret);
        let nullifiers: Vec<[u8; 32]> = note_commitments
            .iter()
            .map(|cm| {
                // For demo, derive rho from commitment; in real wallet use per-note randomness
                let rho = blake3::hash(cm);
                let mut rho32 = [0u8; 32];
                rho32.copy_from_slice(rho.as_bytes());
                derive_nf2(cm, &rho32, &snk)
            })
            .collect();

        // Spend proof binds anchor, inputs and outputs
        let mut bind_hasher = blake3::Hasher::new();
        bind_hasher.update(b"spend_proof_binding:v1");
        bind_hasher.update(&anchor_height.to_le_bytes());
        for c in &note_commitments { bind_hasher.update(c); }
        for o in &output_notes { bind_hasher.update(&o.commitment); }
        let spend_proof = bind_hasher.finalize().as_bytes().to_vec();

        // Output proofs are omitted; node will verify commitments via spend_proof binding
        let spend_proofs = vec![spend_proof.clone()];
        let output_proofs: Vec<Vec<u8>> = Vec::new();

        // Compose a PCD binding proof over current anchor and nullifiers/outputs
        let mut pcd_hasher = blake3::Hasher::new();
        pcd_hasher.update(b"tx_pcd_binding");
        pcd_hasher.update(&anchor_height.to_le_bytes());
        for n in &nullifiers { pcd_hasher.update(n); }
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

    /// Build a node transaction with membership witnesses for spent inputs
    pub async fn build_node_transaction(
        &self,
        spent_inputs: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
        output_commitments: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
    ) -> Result<node_ext::Transaction> {
        // Anchor and roots from current PCD state
        let state = self
            .pcd_manager
            .read()
            .await
            .current_state()
            .cloned()
            .ok_or_else(|| anyhow!("No current PCD state"))?;

        // Create membership witnesses by proving positions from embedded MMR
        let mmr_bytes = state.mmr_raw();
        let mmr: MmrAccumulator = bincode::deserialize(mmr_bytes)
            .map_err(|e| anyhow!("MMR deserialize failed: {}", e))?;

        let mut witnesses: Vec<Vec<u8>> = Vec::new();
        for cm in &spent_inputs {
            if let Some(enc_note) = self.database.get_note(cm).await {
                if let Ok(proof) = mmr.prove(enc_note.position) {
                    let witness = MmrWitness {
                        position: proof.element.position,
                        auth_path: proof
                            .siblings
                            .iter()
                            .map(|s| (s.position, s.hash))
                            .collect(),
                        peaks: proof
                            .peaks
                            .iter()
                            .map(|p| (p.position, p.hash))
                            .collect(),
                    };
                    witnesses.push(bincode::serialize(&witness)?);
                } else {
                    witnesses.push(Vec::new());
                }
            } else {
                witnesses.push(Vec::new());
            }
        }

        // Derive nullifiers (NF2) for spent inputs
        let spend_secret = self.database.get_or_generate_spend_secret().await?;
        let snk = pq_crypto::derive_spend_nullifier_key(&spend_secret);
        let nullifiers: Vec<[u8; 32]> = spent_inputs
            .iter()
            .map(|cm| {
                let rho = blake3::hash(cm);
                let mut rho32 = [0u8; 32];
                rho32.copy_from_slice(rho.as_bytes());
                pq_crypto::derive_nf2(cm, &rho32, &snk)
            })
            .collect();

        // Bind spend proof
        let mut spend_hasher = blake3::Hasher::new();
        spend_hasher.update(b"spend_proof_binding:v1");
        spend_hasher.update(&state.anchor_height.to_le_bytes());
        for n in &nullifiers { spend_hasher.update(n); }
        for c in &output_commitments { spend_hasher.update(c); }
        let spend_proof = spend_hasher.finalize().as_bytes().to_vec();

        // Compose PCD binding proof
        let mut pcd_hasher = blake3::Hasher::new();
        pcd_hasher.update(b"tx_pcd_binding");
        pcd_hasher.update(&state.anchor_height.to_le_bytes());
        for n in &nullifiers { pcd_hasher.update(n); }
        let pcd_proof = pcd_hasher.finalize().as_bytes().to_vec();

        let tx = node_ext::Transaction {
            hash: node_ext::TransactionHash(blake3::hash(b"wallet-tx")),
            nullifiers,
            commitments: output_commitments,
            spent_commitments: spent_inputs,
            membership_witnesses: witnesses,
            pcd_proof,
            pcd_prev_state_commitment: state.state_commitment,
            pcd_new_state_commitment: state.state_commitment,
            pcd_mmr_root: state.mmr_root,
            pcd_nullifier_root: state.nullifier_root,
            anchor_height: state.anchor_height,
            spend_proof,
        };

        Ok(tx)
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

    /// Recompute and persist MMR witnesses for all unspent notes after adopting a new PCD state
    async fn update_witnesses_after_pcd(
        database: &WalletDatabase,
        state: &PcdState,
    ) -> Result<()> {
        let mmr_bytes = state.mmr_raw();
        if mmr_bytes.is_empty() { return Ok(()); }

        let mmr: MmrAccumulator = bincode::deserialize(mmr_bytes)
            .map_err(|e| anyhow!("MMR deserialize failed: {}", e))?;

        let unspent = database.list_unspent_notes().await;
        for enc_note in unspent {
            let pos = enc_note.position;
            if pos >= mmr.size() { continue; }
            if let Ok(proof) = mmr.prove(pos) {
                let witness = MmrWitness {
                    position: proof.element.position,
                    auth_path: proof
                        .siblings
                        .iter()
                        .map(|s| (s.position, s.hash))
                        .collect(),
                    peaks: proof
                        .peaks
                        .iter()
                        .map(|p| (p.position, p.hash))
                        .collect(),
                };
                let witness_bytes = bincode::serialize(&witness)
                    .map_err(|e| anyhow!("Witness serialize failed: {}", e))?;
                let rec = storage::WitnessRecord::new(pos, &witness_bytes, &database.master_key)?;
                let _ = database.upsert_witness(pos, rec).await;
            }
        }
        Ok(())
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
        if self.pcd_proof.is_empty() {
            return Err(anyhow!("Missing PCD proof"));
        }
        if self.inputs.is_empty() && self.outputs.is_empty() {
            return Err(anyhow!("Transaction must have inputs or outputs"));
        }
        // Verify spend proof binding
        if self.spend_proofs.len() != 1 {
            return Err(anyhow!("Expected a single aggregated spend proof"));
        }
        let mut h = blake3::Hasher::new();
        h.update(b"spend_proof_binding:v1");
        h.update(&self.anchor_height.to_le_bytes());
        for i in &self.inputs { h.update(i); }
        for o in &self.outputs { h.update(&o.commitment); }
        let expected = h.finalize();
        if self.spend_proofs[0].as_slice() != expected.as_bytes() {
            return Err(anyhow!("Spend proof binding mismatch"));
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
