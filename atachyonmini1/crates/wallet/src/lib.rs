#![forbid(unsafe_code)]
//! # wallet
//!
//! Tachyon wallet implementation providing secure note management,
//! PCD state synchronization, and transaction construction.

use anyhow::{anyhow, Result};
#[cfg(feature = "pcd")]
use tachyon_core::{BlobKind, Cid, ControlMessage, TachyonNetwork, SyncManifest};
#[cfg(feature = "pcd")]
use tachyon_zk::{
    PcdCore as Halo2PcdCore,
    compute_transition_digest_bytes,
    compute_wallet_state_root_bytes_checked,
    compute_wallet_agg_final_bytes_checked,
};
#[cfg(feature = "pcd")]
use pq_crypto::{
    derive_nf2, derive_spend_nullifier_key, KyberPublicKey, KyberSecretKey,
    OutOfBandPayment, SimpleKem, SuiteB,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, sync::Arc};
use storage::{EncryptedNote, PcdStateRecord, WalletDatabase, NOTE_COMMITMENT_SIZE};
use tokio::{
    sync::{broadcast, mpsc, RwLock, Semaphore},
    task::JoinHandle,
};
#[cfg(feature = "pcd")]
use reqwest::Client as HttpClient;
#[cfg(feature = "pcd")]
use tachyon_core::HTTP_CLIENT;
#[cfg(feature = "pcd")]
use tachyon_zk::{RecursionCore as ProofRecursionCore};
use tachyon_zk::wallet_step::{prove_wallet_step, verify_wallet_step};
use tachyon_zk::tachyon::{Tachystamp, Tachygram, Tachyaction, TachyAnchor, TachyOpKind};
use pasta_curves::Fp as Fr;
#[cfg(feature = "pcd")]
use crate::dex::{DexService, Side as DexSide, Price as DexPrice, Quantity as DexQty, OwnerId as DexOwnerId, OrderId as DexOrderId, OrderBookSnapshot as DexSnapshot, Trade as DexTrade};
use halo2_gadgets::poseidon::primitives::{self as poseidon_primitives, ConstantLength, P128Pow5T3};
#[cfg(feature = "pcd")]
use tachyon_zk::{MmrAccumulator, MmrWitness};
// duplicate import removed
use ff::{PrimeField, FromUniformBytes};
#[cfg(feature = "pcd")]
use tachyon_zk::orchard::prove_spend_link;

#[cfg(feature = "zcash")]
mod zcash;

/// Wallet configuration
#[derive(Clone)]
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

impl std::fmt::Debug for WalletConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletConfig")
            .field("db_path", &self.db_path)
            .field("master_password", &"<redacted>")
            .field("network_config", &self.network_config)
            .field("sync_config", &self.sync_config)
            .finish()
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        // Default is suitable for local development/tests only. Use from_env() for production.
        Self {
            db_path: "./wallet_db".to_string(),
            master_password: String::new(),
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
        let master_password = get("TACHYON_MASTER_PASSWORD").unwrap_or_else(String::new);

        let data_dir = get("TACHYON_IROH_DATA_DIR").unwrap_or_else(|| "./wallet_data".to_string());
        let bootstrap_nodes = get("TACHYON_BOOTSTRAP_NODES")
            .map(|s| {
                s.split(',')
                    .filter(|x| !x.is_empty())
                    .map(|s| s.trim().to_string())
                    .collect()
            })
            .unwrap_or_else(Vec::new);

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

        let insecure_password = self.master_password.is_empty() || self.master_password == "default_password";
        let insecure_oss = self
            .sync_config
            .oss_endpoints
            .iter()
            .any(|e| e.contains("localhost"));

        if (insecure_password || insecure_oss) && !allow_insecure {
            return Err(anyhow!(
                "Insecure configuration: {}{}. Set secure values or TACHYON_ALLOW_INSECURE=1 for development.",
                if insecure_password { "MASTER_PASSWORD is empty or default. " } else { "" },
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

// Disabled: parsing EncryptedNote without decryption encourages misuse.
// Use parse_wallet_note_from_plaintext with proper decryption instead.

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
    #[cfg(feature = "pcd")]
    network: Arc<TachyonNetwork>,
    /// PCD state manager
    #[cfg(feature = "pcd")]
    pcd_manager: Arc<RwLock<PcdStateManager<SimplePcdVerifier>>>,
    /// PCD sync manager
    #[cfg(feature = "pcd")]
    sync_manager: Arc<RwLock<Option<PcdSyncManager<WalletSyncClient, SimplePcdVerifier>>>>,
    /// OOB payment handler
    #[cfg(feature = "pcd")]
    oob_handler: Arc<RwLock<OutOfBandHandler>>,
    /// Background sync task
    sync_task: Option<JoinHandle<()>>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// In-memory DEX service (single-market) for demo
    #[cfg(feature = "pcd")]
    dex: Arc<DexService>,
    /// Optional Zcash context
    #[cfg(feature = "zcash")]
    zcash: Option<zcash::ZcashContext>,
}

/// Out-of-band payment handler
#[cfg(feature = "pcd")]
pub struct OutOfBandHandler {
    /// Our Kyber secret key for decrypting OOB payments
    secret_key: KyberSecretKey,
    /// Pending OOB payments
    pending_payments: HashMap<[u8; 32], OutOfBandPayment>, // Keyed by payment hash
}

#[cfg(feature = "pcd")]
impl OutOfBandHandler {
    /// Create a new OOB handler
    pub fn new(secret_key: KyberSecretKey) -> Result<Self> {
        Ok(Self {
            secret_key,
            pending_payments: HashMap::new(),
        })
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
#[cfg(feature = "pcd")]
pub struct WalletSyncClient {
    /// Network client reference
    network: Arc<TachyonNetwork>,
    /// Blob announcement receiver
    announcements: broadcast::Receiver<(BlobKind, Cid, u64, usize, String)>,
    /// Concurrency limiter for network fetches
    fetch_sema: Arc<Semaphore>,
}

#[cfg(feature = "pcd")]
impl WalletSyncClient {
    /// Create a new sync client
    pub fn new(network: Arc<TachyonNetwork>, fetch_sema: Arc<Semaphore>) -> Self {
        let announcements = network.subscribe_announcements();
        Self { network, announcements, fetch_sema }
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
                // Acquire a permit before fetching over the network
                if self.fetch_sema.acquire().await.is_err() { return Ok(None); }
                let bytes = self.network.fetch_blob_from_ticket(&ticket).await?;
                Ok(Some((kind, bytes.to_vec())))
            }
            Err(_) => Ok(None),
        }
    }
}
#[cfg(feature = "pcd")]
/// Minimal Zebra nullifier client (HTTP JSON), feature-gated by env var
struct ZebraNullifierClient {
    base_url: String,
    http: HttpClient,
}

#[cfg(feature = "pcd")]
impl ZebraNullifierClient {
    fn new(base_url: String) -> Self { Self { base_url, http: HTTP_CLIENT.clone() } }

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


#[cfg(feature = "pcd")]
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
    ) -> Result<Option<tachyon_zk::PcdDeltaBundle>> {
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
        Ok(Some(tachyon_zk::PcdDeltaBundle::new(mmr_segments, nf_segments, (start_height, end_height))))
    }

    async fn fetch_transition_proof(
        &self,
        prev_height: u64,
        new_height: u64,
    ) -> Result<Option<Vec<u8>>> {
        tracing::debug!("Fetching transition proof for {} to {}", prev_height, new_height);
        // Prefer the manifest to locate the transition ticket precisely
        let anns = self.network.get_recent_announcements();
        let mut manifests: Vec<(u64, String)> = anns
            .into_iter()
            .filter(|(k, _cid, h, _s, _t)| *k == BlobKind::Manifest && *h == new_height)
            .map(|(_k, _cid, h, _s, t)| (h, t))
            .collect();
        manifests.sort_by_key(|(h, _)| *h);
        for (_h, ticket) in manifests {
            if let Ok(bytes) = self.network.fetch_blob_from_ticket(&ticket).await {
                if let Ok(manifest) = serde_json::from_slice::<SyncManifest>(&bytes) {
                    if let Some(item) = manifest.items.into_iter().find(|i| matches!(i.kind, BlobKind::PcdTransition)) {
                        if let Ok(p) = self.network.fetch_blob_from_ticket(&item.ticket).await {
                            return Ok(Some(p.to_vec()));
                        }
                    }
                }
            }
        }
        // Fallback: look in local published cache
        let published = self.network.get_published().await;
        Ok(published
            .into_iter()
            .find(|(k, _b, h)| matches!(k, BlobKind::PcdTransition) && *h == new_height)
            .map(|(_k, b, _h)| b))
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
                config.validate()?;
            }
        }
        // Initialize encrypted database
        let db_path = Path::new(&config.db_path);
        let database = Arc::new(WalletDatabase::new(db_path, &config.master_password).await?);

        // Initialize network client
        #[cfg(feature = "pcd")]
        let network = {
            let network_path = Path::new(&config.network_config.data_dir);
            Arc::new(TachyonNetwork::new(network_path).await?)
        };

        // Initialize PCD state manager
        #[cfg(feature = "pcd")]
        let verifier = SimplePcdVerifier;
        #[cfg(feature = "pcd")]
        let pcd_manager = Arc::new(RwLock::new(PcdStateManager::new(verifier)));

        // Ensure OOB keypair exists and load it
        #[cfg(feature = "pcd")]
        let (_pk, sk) = database.get_or_generate_oob_keypair().await?;

        // Initialize OOB handler with persisted secret key
        #[cfg(feature = "pcd")]
        let oob_handler = Arc::new(RwLock::new(OutOfBandHandler::new(sk)?));

        // Initialize sync manager
        #[cfg(feature = "pcd")]
        let sync_client = WalletSyncClient::new(network.clone(), Arc::new(Semaphore::new(8)));
        #[cfg(feature = "pcd")]
        let sync_manager = Arc::new(RwLock::new(Some(PcdSyncManager::new(
            sync_client,
            SimplePcdVerifier,
        ))));

        // Default: enable persistent DEX engine under the wallet DB path.
        #[cfg(feature = "pcd")]
        let dex = {
            let sled_path = std::path::Path::new(&config.db_path).join("dex_sled");
            let snap_path = std::path::Path::new(&config.db_path).join("dex").join("orderbook.bin");
            if let Ok(engine) = dex::SledEngine::open(&sled_path) {
                DexService::with_engine_and_snapshot(Arc::new(engine), &snap_path)
            } else {
                DexService::with_snapshot(&snap_path)
            }
        };

        Ok(Self {
            config,
            database,
            #[cfg(feature = "pcd")]
            network,
            #[cfg(feature = "pcd")]
            pcd_manager,
            #[cfg(feature = "pcd")]
            sync_manager,
            #[cfg(feature = "pcd")]
            oob_handler,
            sync_task: None,
            shutdown_tx: None,
            #[cfg(feature = "pcd")]
            dex: Arc::new(dex),
            #[cfg(feature = "zcash")]
            zcash: None,
        })
    }

    /// Build a Tachystamp for a wallet-originated transaction: wraps tx proofs and outputs
    #[cfg(feature = "pcd")]
    pub async fn build_tachystamp(
        &self,
        outputs: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
        nullifiers: Vec<[u8; 32]>,
        action_pairs: Vec<([u8; 32], [u8; 32])>,
        action_bindings: Vec<[u8; 32]>,
        action_sigs: Vec<Vec<u8>>,
        proofs: Vec<Vec<u8>>,
    ) -> Result<Tachystamp> {
        let state = self
            .pcd_manager
            .read()
            .await
            .current_state()
            .cloned()
            .ok_or_else(|| anyhow!("No current PCD state"))?;

        // Collect tachygrams (commitments first, then nullifiers)
        let mut grams: Vec<Tachygram> = Vec::new();
        for cm in outputs { grams.push(Tachygram(cm)); }
        for nf in nullifiers { grams.push(Tachygram(nf)); }

        // Build actions from provided pairs and bindings/signatures
        let mut actions: Vec<Tachyaction> = Vec::new();
        for (idx, (l, r)) in action_pairs.into_iter().enumerate() {
            let binding = action_bindings.get(idx).cloned().unwrap_or([0u8; 32]);
            let sig = action_sigs.get(idx).cloned().unwrap_or_default();
            actions.push(Tachyaction {
                left: Tachygram(l),
                right: Tachygram(r),
                op: TachyOpKind::Bind,
                binding_digest: binding,
                auth_signature: sig,
            });
        }

        // Anchor is the current state roots/height
        let anchor = TachyAnchor { height: state.anchor_height, mmr_root: state.mmr_root, nullifier_root: state.nullifier_root };

        // Aggregate provided proofs into a Tachystamp using safe Fiat–Shamir recursion
        let core = ProofRecursionCore::new()?;
        let (agg_proof, agg_commit, fs_prev, fs_cur) = if proofs.is_empty() {
            (Vec::new(), [0u8; 32], [0u8; 32], [0u8; 32])
        } else {
            core.aggregate_many_proofs_fs_with_witness(&proofs)?
        };
        let stamp = Tachystamp {
            anchor,
            tachygrams: grams,
            actions,
            aggregated_proof: agg_proof,
            aggregated_commitment: agg_commit,
            fs_prev_commitment: fs_prev,
            fs_current_commitment: fs_cur,
        };
        Ok(stamp)
    }

    /// Initialize wallet with genesis state
    #[cfg(feature = "pcd")]
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

    #[cfg(not(feature = "pcd"))]
    pub async fn initialize(&mut self) -> Result<()> {
        // No-op when PCD is disabled
        Ok(())
    }

    // ===== Zcash: seed and address APIs =====
    #[cfg(all(feature = "zcash", feature = "zcash_mnemonic"))]
    /// Import a Zcash seed (BIP-39 mnemonic) and birthday height (mainnet). Overwrites existing.
    pub async fn zcash_import_seed(&self, mnemonic: &str, birthday_height: u64) -> Result<()> {
        // Mnemonic parsing is disabled; accept raw string for now
        self.database.set_zcash_seed(mnemonic, birthday_height).await
    }

    #[cfg(all(feature = "zcash", feature = "zcash_mnemonic"))]
    /// Export the stored Zcash seed and birthday height.
    pub async fn zcash_export_seed(&self) -> Result<(String, u64)> {
        self.database
            .get_zcash_seed()
            .await
            .ok_or_else(|| anyhow!("No Zcash seed stored"))
    }

    #[cfg(feature = "zcash")]
    /// Get a Unified Address (UA) for receiving on mainnet/testnet based on stored seed.
    pub async fn zcash_get_unified_address(&mut self) -> Result<String> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.get_ua().await
    }

    #[cfg(feature = "zcash")]
    /// Connect to lightwalletd and scan up to the given height. Returns scanned height and balance (zatoshi).
    pub async fn zcash_sync_to_height(&mut self, target_height: u64) -> Result<(u64, u64)> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_mut().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.sync_to_height(target_height).await
    }

    #[cfg(feature = "zcash")]
    /// Get current Orchard spendable balance (zatoshi) per derived account 0.
    pub async fn zcash_get_balance(&mut self) -> Result<u64> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.get_balance().await
    }

    #[cfg(feature = "zcash")]
    /// Send an Orchard transaction to `to_ua` with `amount_zat` and optional `memo`.
    pub async fn zcash_send(
        &mut self,
        to_ua: &str,
        amount_zat: u64,
        memo: Option<String>,
    ) -> Result<(String, u64)> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_mut().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.send_shielded(to_ua, amount_zat, memo.as_deref()).await
    }

    #[cfg(feature = "zcash")]
    /// Multi-account: set default account id
    pub async fn zcash_set_default_account(&mut self, account: u32) -> Result<()> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.set_default_account(account)
    }

    #[cfg(feature = "zcash")]
    /// List accounts with UAs (best-effort)
    pub async fn zcash_list_accounts(&mut self) -> Result<Vec<(u32, String)>> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.list_accounts().await
    }

    #[cfg(feature = "zcash")]
    /// Rescan from a height to a target height
    pub async fn zcash_rescan(&mut self, start_height: u64, target_height: u64) -> Result<u64> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_mut().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.rescan_from_height(start_height, target_height).await
    }

    #[cfg(feature = "zcash")]
    /// Set a local checkpoint height for faster future scans
    pub async fn zcash_set_checkpoint(&mut self, height: u64) -> Result<()> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.set_checkpoint(height).await
    }

    #[cfg(feature = "zcash")]
    /// Export Zcash wallet backup to directory
    pub async fn zcash_export_backup(&mut self, dst_dir: &str) -> Result<()> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.export_backup(dst_dir).await
    }

    #[cfg(feature = "zcash")]
    /// Import Zcash wallet backup from directory
    pub async fn zcash_import_backup(&mut self, src_dir: &str) -> Result<()> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.import_backup(src_dir).await
    }

    #[cfg(feature = "zcash")]
    async fn ensure_zcash_context_initialized(&mut self) -> Result<()> {
        if self.zcash.is_some() {
            return Ok(());
        }
        let (mnemonic, birthday) = self
            .database
            .get_zcash_seed()
            .await
            .ok_or_else(|| anyhow!("No Zcash seed stored"))?;

        // Load env config
        let lwd_url = std::env::var("ZCASH_LWD_URL").unwrap_or_else(|_| "https://mainnet.lightwalletd.com:9067".to_string());
        let network = std::env::var("ZCASH_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

        let ctx = zcash::ZcashContext::new(&self.config.db_path, &mnemonic, birthday, &lwd_url, &network).await?;
        self.zcash = Some(ctx);
        Ok(())
    }

    // ===== Zcash: key export and ZIP-321 helpers =====
    #[cfg(feature = "zcash")]
    /// Export UFVK for an account (ZIP-32)
    pub async fn zcash_export_ufvk(&mut self, account: u32) -> Result<String> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.export_ufvk(account).await
    }

    #[cfg(feature = "zcash")]
    /// Export USK for an account (ZIP-32)
    pub async fn zcash_export_usk(&mut self, account: u32) -> Result<String> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.export_usk(account).await
    }

    #[cfg(feature = "zcash")]
    /// Generate a ZIP-321 payment URI
    pub async fn zcash_generate_payment_uri(
        &mut self,
        to_ua: &str,
        amount_zat: u64,
        memo: Option<String>,
    ) -> Result<String> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.generate_payment_uri(to_ua, amount_zat, memo.as_deref()).map_err(Into::into)
    }

    #[cfg(feature = "zcash")]
    /// Parse a ZIP-321 payment URI -> (ua, amount_zat, memo)
    pub async fn zcash_parse_payment_uri(&mut self, uri: &str) -> Result<(String, u64, Option<String>)> {
        self.ensure_zcash_context_initialized().await?;
        let ctx = self.zcash.as_ref().ok_or_else(|| anyhow!("Zcash context not initialized"))?;
        ctx.parse_payment_uri(uri)
    }

    /// Start background synchronization task
    #[cfg(feature = "pcd")]
    async fn start_sync_task(&mut self) -> Result<()> {
        if self.sync_task.is_some() { return Ok(()); }
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        let sync_manager = self.sync_manager.clone();
        let network = self.network.clone();
        let sync_interval = self.config.sync_config.sync_interval_secs;
        let pcd_manager = self.pcd_manager.clone();
        let database = self.database.clone();

        // Optional Zebra nullifier client (chain-sourced nullifier set)
        let zebra_url_opt = std::env::var("TACHYON_ZEBRA_NULLIFIER_URL").ok();
        let privacy_oblivious = std::env::var("TACHYON_PRIVACY_OBLIVIOUS").unwrap_or_default() == "1";
        let zebra_client = zebra_url_opt
            .as_ref()
            .map(|u| ZebraNullifierClient::new(u.clone()));

        let sync_task = tokio::spawn(async move {
            // Subscribe to blob announcements
            let mut client = WalletSyncClient::new(network.clone(), Arc::new(Semaphore::new(8)));
            let _ = client.subscribe_to_sync_blobs().await;

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sync_interval));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Determine latest observed height once for this tick
                        let latest_height = {
                            let published = network.get_published().await;
                            published.iter().map(|p| p.2).max().unwrap_or(0)
                        };

                        // Perform sync operation
                        if let Some(sync_mgr) = sync_manager.write().await.as_mut() {
                            if let Err(e) = sync_mgr.sync_to_height(latest_height).await {
                                tracing::error!("Sync failed: {}", e);
                            }
                        }

                        // Chain-sourced nullifier check via Zebra if configured and privacy allows
                        if !privacy_oblivious {
                            if let Some(ref client) = zebra_client {
                            let unspent = database.list_unspent_notes().await;
                            // Derive NF2 for each unspent note and check against chain nullifiers
                            if let Ok(spend_secret) = database.get_or_generate_spend_secret().await {
                                let snk = derive_spend_nullifier_key(&spend_secret);
                                // Determine a starting height for fetching nullifiers
                                let start_h = database.get_chain_nf_last_height().await;
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
                                    // Advance last scanned height to latest observed height
                                    let latest_height = {
                                        let published = network.get_published().await;
                                        published.iter().map(|p| p.2).max().unwrap_or(0)
                                    };
                                    let _ = database.set_chain_nf_last_height(latest_height).await;
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
                                        // Apply transition to local PCD state and persist; gaps are handled by periodic manifest sync
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

    #[cfg(not(feature = "pcd"))]
    async fn start_sync_task(&mut self) -> Result<()> { Ok(()) }

    /// Stop the wallet and cleanup resources
    pub async fn shutdown(&mut self) -> Result<()> {
        // Stop sync task
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        if let Some(sync_task) = self.sync_task.take() {
            sync_task.await?;
        }

        #[cfg(feature = "pcd")]
        {
            // Gracefully shutdown network router
            self.network.shutdown().await?;
        }

        Ok(())
    }

    /// Get wallet statistics
    pub async fn get_stats(&self) -> Result<WalletStats> {
        let db_stats = self.database.get_stats().await;

        #[cfg(feature = "pcd")]
        let current_anchor = self
            .pcd_manager
            .read()
            .await
            .current_state()
            .map(|s| s.anchor_height);

        #[cfg(not(feature = "pcd"))]
        let current_anchor: Option<u64> = None;

        #[cfg(feature = "pcd")]
        let pending_oob = self.oob_handler.read().await.pending_payments.len();

        #[cfg(not(feature = "pcd"))]
        let pending_oob: usize = 0;

        Ok(WalletStats {
            db_stats,
            network_connected: cfg!(feature = "pcd"),
            current_anchor_height: current_anchor,
            pending_payments: pending_oob,
        })
    }

    /// Get balances (available and locked) for USDC and base asset
    pub async fn get_balances(&self) -> Result<(u64, u64, u64, u64)> {
        Ok((
            self.database.get_usdc_balance().await,
            self.database.get_locked_usdc().await,
            self.database.get_base_balance().await,
            self.database.get_locked_base().await,
        ))
    }

    /// Deposit USDC into the wallet
    pub async fn deposit_usdc(&self, amount: u64) -> Result<()> {
        self.database.deposit_usdc(amount).await
    }

    /// Deposit base asset units (for demo/testing)
    pub async fn deposit_base(&self, amount: u64) -> Result<()> {
        self.database.deposit_base(amount).await
    }

    /// Place a limit order and lock funds accordingly. Returns order id and trades executed.
    #[cfg(feature = "pcd")]
    pub async fn place_limit_order(&self, side: DexSide, price: u64, qty: u64) -> Result<(DexOrderId, Vec<DexTrade>)> {
        match side {
            DexSide::Bid => {
                let required_quote = price.saturating_mul(qty);
                self.database.lock_usdc(required_quote).await?;
            }
            DexSide::Ask => {
                self.database.lock_base(qty).await?;
            }
        }

        let owner = DexOwnerId(self.database.get_or_create_dex_owner_id().await?);
        let (id, trades) = self.dex.place_limit(owner, side, DexPrice(price), DexQty(qty))?;
        // Settle trades: move between locked and available balances
        for t in &trades {
            match t.taker_side {
                DexSide::Bid => {
                    // We are the taker (bid) only if owner matches; for demo we assume owner id=1
                    if t.taker_owner.0 == owner.0 {
                        self.database.settle_bid_fill(t.quantity.0, t.price.0.saturating_mul(t.quantity.0)).await?;
                    } else if t.maker_owner.0 == owner.0 {
                        self.database.settle_ask_fill(t.quantity.0, t.price.0.saturating_mul(t.quantity.0)).await?;
                    }
                }
                DexSide::Ask => {
                    if t.taker_owner.0 == owner.0 {
                        self.database.settle_ask_fill(t.quantity.0, t.price.0.saturating_mul(t.quantity.0)).await?;
                    } else if t.maker_owner.0 == owner.0 {
                        self.database.settle_bid_fill(t.quantity.0, t.price.0.saturating_mul(t.quantity.0)).await?;
                    }
                }
            }
        }

        // If any residual locked funds remain on this order, they stay locked until cancel or fill.
        Ok((id, trades))
    }

    /// Place a market order. Locks max expected spend for bids (estimation) and base for asks.
    #[cfg(feature = "pcd")]
    pub async fn place_market_order(&self, side: DexSide, qty: u64) -> Result<(DexOrderId, Vec<DexTrade>)> {
        match side {
            DexSide::Bid => {
                // Estimate cost at current book; lock that much USDC
                let (filled, cost) = self.dex.estimate_market_cost(DexSide::Bid, DexQty(qty));
                if filled == 0 { return Ok((DexOrderId(0), Vec::new())); }
                self.database.lock_usdc(cost).await?;
                let owner = DexOwnerId(self.database.get_or_create_dex_owner_id().await?);
                let (id, trades) = self.dex.place_market(owner, DexSide::Bid, DexQty(qty))?;
                // Settle trades and refund any unused locked USDC
                let mut spent = 0u64;
                for t in &trades {
                    let trade_cost = t.price.0.saturating_mul(t.quantity.0);
                    if t.taker_owner.0 == owner.0 {
                        // We are market buyer: spend locked USDC, receive base
                        spent = spent.saturating_add(trade_cost);
                        self.database.settle_bid_fill(t.quantity.0, trade_cost).await?;
                    } else if t.maker_owner.0 == owner.0 {
                        // We were maker on ask: spend locked base, receive USDC
                        self.database.settle_ask_fill(t.quantity.0, trade_cost).await?;
                    }
                }
                if cost > spent { self.database.unlock_usdc(cost - spent).await?; }
                Ok((id, trades))
            }
            DexSide::Ask => {
                self.database.lock_base(qty).await?;
                let owner = DexOwnerId(self.database.get_or_create_dex_owner_id().await?);
                let (id, trades) = self.dex.place_market(owner, DexSide::Ask, DexQty(qty))?;
                let mut sold = 0u64;
                for t in &trades {
                    let trade_gain = t.price.0.saturating_mul(t.quantity.0);
                    if t.taker_owner.0 == owner.0 {
                        // We are market seller: spend locked base, receive USDC
                        sold = sold.saturating_add(t.quantity.0);
                        self.database.settle_ask_fill(t.quantity.0, trade_gain).await?;
                    } else if t.maker_owner.0 == owner.0 {
                        // We were maker on bid: spend locked USDC, receive base
                        self.database.settle_bid_fill(t.quantity.0, trade_gain).await?;
                    }
                }
                if qty > sold { self.database.unlock_base(qty - sold).await?; }
                Ok((id, trades))
            }
        }
    }

    /// Cancel an order and unlock remaining locked funds.
    #[cfg(feature = "pcd")]
    pub async fn cancel_order(&self, id: DexOrderId) -> Result<bool> {
        if let Some(order) = self.dex.get_order(id) {
            let ok = self.dex.cancel(id)?;
            if ok {
                match order.side {
                    DexSide::Bid => {
                        let remaining_cost = order.price.0.saturating_mul(order.remaining.0);
                        self.database.unlock_usdc(remaining_cost).await?;
                    }
                    DexSide::Ask => {
                        self.database.unlock_base(order.remaining.0).await?;
                    }
                }
            }
            Ok(ok)
        } else {
            Ok(false)
        }
    }

    /// Get orderbook snapshot
    #[cfg(feature = "pcd")]
    pub fn orderbook(&self, depth: usize) -> DexSnapshot { self.dex.orderbook(depth) }

    /// Get recent trades
    #[cfg(feature = "pcd")]
    pub fn trades(&self, limit: usize) -> Vec<DexTrade> { self.dex.recent_trades(limit) }

    /// Receive an out-of-band payment
    #[cfg(feature = "pcd")]
    pub async fn receive_oob_payment(&self, payment: OutOfBandPayment) -> Result<[u8; 32]> {
        let mut handler = self.oob_handler.write().await;
        handler.add_pending_payment(payment)
    }

    /// Process a pending OOB payment
    #[cfg(feature = "pcd")]
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
                .unwrap_or_else(Vec::new);
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
    #[cfg(feature = "pcd")]
    pub async fn create_oob_payment(
        &self,
        recipient_pk: KyberPublicKey,
        note_data: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<OutOfBandPayment> {
        OutOfBandPayment::new(recipient_pk, &note_data, associated_data)
    }

    /// Get our public key for OOB payments
    #[cfg(feature = "pcd")]
    pub async fn get_oob_public_key(&self) -> KyberPublicKey {
        // Retrieve from storage to avoid accidental regeneration
        if let Ok(Some((pk, _))) = self.database.get_oob_keypair().await {
            pk
        } else {
            // Should not happen; fallback to ephemeral for continuity
            // Return a zero key if generation fails (caller should check)
            SimpleKem::generate_keypair()
                .map(|(pk, _)| pk)
                .unwrap_or_else(|_| KyberPublicKey::new(vec![0u8; 32]))
        }
    }

    /// Send an out-of-band payment over Iroh to a specific peer.
    #[cfg(feature = "pcd")]
    pub async fn send_oob_over_iroh(&self, peer: tachyon_core::NodeId, payment: OutOfBandPayment) -> Result<[u8; 32]> {
        payment.verify()?;
        let h = blake3::hash(payment.encrypted_metadata.as_slice());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(h.as_bytes());
        // Serialize payment to bytes (JSON) for transport
        let bytes = serde_json::to_vec(&payment)?;
        self.network.send_oob_to_peer(peer, hash_bytes, bytes).await?;
        Ok(hash_bytes)
    }

    /// Subscribe to incoming out-of-band payments.
    #[cfg(feature = "pcd")]
    pub fn subscribe_incoming_oob(&self) -> tokio::sync::broadcast::Receiver<([u8; 32], Vec<u8>, tachyon_core::NodeId)> {
        self.network.subscribe_oob_payments()
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

    /// Compute Orchard-style note commitment over Pasta Poseidon2: cm = H(TAG, pk, v)
    fn orchard_note_commitment(pk: Fr, value: Fr) -> [u8; 32] {
        let tag = Fr::from(101u64);
        let cm = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([tag, pk, value]);
        let mut out = [0u8; 32];
        out.copy_from_slice(cm.to_repr().as_ref());
        out
    }

    /// Compute Orchard-style nullifier: nf = H(TAG, cm, rho)
    fn orchard_nullifier(cm: [u8; 32], rho32: [u8; 32]) -> [u8; 32] {
        let cm_f = {
            let mut repr = <Fr as ff::PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&cm);
            Fr::from_repr(repr).unwrap_or_else(|| {
                // Fallback: uniform map from bytes if not canonical
                use std::io::Read as _; let mut h = blake3::Hasher::new(); h.update(b"orch:nf:map:v1"); h.update(&cm); let mut xof = h.finalize_xof(); let mut wide = [0u8; 64];
                // XOF read from BLAKE3 should never fail with a fixed-size buffer
                let _ = xof.read_exact(&mut wide);
                Fr::from_uniform_bytes(&wide)
            })
        };
        let rho_f = {
            let mut repr = <Fr as ff::PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&rho32);
            Fr::from_repr(repr).unwrap_or_else(|| {
                use std::io::Read as _; let mut h = blake3::Hasher::new(); h.update(b"orch:nf:rho:v1"); h.update(&rho32); let mut xof = h.finalize_xof(); let mut wide = [0u8; 64];
                // XOF read from BLAKE3 should never fail with a fixed-size buffer
                let _ = xof.read_exact(&mut wide);
                Fr::from_uniform_bytes(&wide)
            })
        };
        let tag = Fr::from(102u64);
        let nf = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([tag, cm_f, rho_f]);
        let mut out = [0u8; 32];
        out.copy_from_slice(nf.to_repr().as_ref());
        out
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
                // For production Orchard-like, rho should be per-note randomness; derive deterministically here
                let rho = blake3::hash(cm);
                let mut rho32 = [0u8; 32];
                rho32.copy_from_slice(rho.as_bytes());
                // Keep NF2 derivation path but also compute Orchard-style nullifier for compatibility tests
                let _nf_orch = Self::orchard_nullifier(*cm, rho32);
                derive_nf2(cm, &rho32, &snk)
            })
            .collect();

        // Compute output commitments via Orchard-like Poseidon2 for recipients
        let output_commitments: Vec<[u8; 32]> = output_notes
            .iter()
            .map(|n| {
                let pk_f = {
                    use std::io::Read as _; let mut h = blake3::Hasher::new(); h.update(b"orch:pk:map:v1"); h.update(&n.recipient); let mut xof = h.finalize_xof(); let mut wide = [0u8; 64];
                    // XOF read from BLAKE3 should never fail with a fixed-size buffer
                    let _ = xof.read_exact(&mut wide);
                    Fr::from_uniform_bytes(&wide)
                };
                let val_f = Fr::from(n.value);
                Self::orchard_note_commitment(pk_f, val_f)
            })
            .collect();

        // Spend proof binds anchor, inputs and outputs
        let mut bind_hasher = blake3::Hasher::new();
        bind_hasher.update(b"spend_proof_binding:v1");
        bind_hasher.update(&anchor_height.to_le_bytes());
        for c in &note_commitments { bind_hasher.update(c); }
        for c in &output_commitments { bind_hasher.update(c); }
        let spend_proof = bind_hasher.finalize().as_bytes().to_vec();

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
            outputs: output_commitments,
            spend_proofs,
            output_proofs,
            nullifiers,
            anchor_height,
            pcd_proof,
        })
    }

    /// Build a node transaction with membership witnesses for spent inputs
    #[cfg(feature = "pcd")]
    pub async fn build_node_transaction(
        &self,
        spent_inputs: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
        output_commitments: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
    ) -> Result<_node_ext_dep_check::Transaction> {
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

        // Generate SMT-16 non-membership proofs from embedded nullifier SMT in the PCD state if present
        let mut nullifier_non_membership: Vec<Vec<u8>> = Vec::new();
        if !state.nullifier_raw().is_empty() {
            if let Ok(smt) = bincode::deserialize::<accum_set::Smt16Accumulator>(state.nullifier_raw()) {
                for nf in &nullifiers {
                    if let Ok(proof) = smt.create_non_membership_witness(nf) {
                        if proof.verify_for_key(nf, &state.nullifier_root) {
                            if let Ok(bytes) = bincode::serialize(&proof) {
                                nullifier_non_membership.push(bytes);
                                continue;
                            }
                        }
                    }
                    nullifier_non_membership.push(Vec::new());
                }
            } else {
                nullifier_non_membership = vec![Vec::new(); nullifiers.len()];
            }
        } else {
            nullifier_non_membership = vec![Vec::new(); nullifiers.len()];
        }

        // Bind spend proof
        let mut spend_hasher = blake3::Hasher::new();
        spend_hasher.update(b"spend_proof_binding:v1");
        spend_hasher.update(&state.anchor_height.to_le_bytes());
        for n in &nullifiers { spend_hasher.update(n); }
        for c in &output_commitments { spend_hasher.update(c); }
        let spend_proof = spend_hasher.finalize().as_bytes().to_vec();

        // Compute PCD transition digest for new_state and generate Halo2 proof bound to current roots
        let prev_state = state.state_commitment;
        let new_state = compute_transition_digest_bytes(
            &prev_state,
            &state.mmr_root,
            &state.nullifier_root,
            state.anchor_height,
        );
        let (keys_dir, k) = tachyon_zk::pcd_keys_config();
        let halo2 = Halo2PcdCore::load_or_setup(keys_dir.as_path(), k)?;
        let pcd_proof = halo2.prove_transition(
            &prev_state,
            &new_state,
            &state.mmr_root,
            &state.nullifier_root,
            state.anchor_height,
        )?;

        let _num_spent = spent_inputs.len();

        // Helper: map arbitrary bytes deterministically into canonical field encoding
        #[inline]
        fn to_canonical_fr_bytes(src: &[u8]) -> [u8; 32] {
            if src.len() >= 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&src[..32]);
                if let Some(fr) = Option::<Fr>::from(Fr::from_repr(arr)) {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(fr.to_repr().as_ref());
                    return out;
                }
            }
            use std::io::Read as _;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"wallet:uniform_fr:v1");
            hasher.update(src);
            let mut wide = [0u8; 64];
            let _ = hasher.finalize_xof().read_exact(&mut wide);
            let fr = Fr::from_uniform_bytes(&wide);
            let mut out = [0u8; 32];
            out.copy_from_slice(fr.to_repr().as_ref());
            out
        }

        // Precompute canonical state_root once
        let state_root = compute_wallet_state_root_bytes_checked(&state.mmr_root, &state.nullifier_root)
            .ok_or_else(|| anyhow!("non-canonical state roots for wallet actions"))?;

        // For each spend input/nullifier, generate SpendLink proof and a SuiteB signature
        let mut action_links: Vec<[u8; 32]> = Vec::with_capacity(nullifiers.len());
        let mut actions: Vec<_node_ext_dep_check::Action> = Vec::with_capacity(nullifiers.len());

        // Generate a single SuiteB keypair to authorize all spends in this tx (prototype)
        let (suite_pk, suite_sk) = SuiteB::generate_keypair()?;
        // Compress/derive 32-byte rk_bytes from SuiteB pk deterministically for the prototype
        let rk_bytes32 = {
            let h = blake3::hash(suite_pk.as_bytes());
            let mut out = [0u8; 32];
            out.copy_from_slice(h.as_bytes());
            out
        };

        for (i, nf) in nullifiers.iter().copied().enumerate() {
            // cmx ties to spent commitment at same index
            let mut cmx32 = [0u8; 32];
            if let Some(cmx_src) = spent_inputs.get(i) { cmx32.copy_from_slice(cmx_src); }

            // Derive per-note randomness rho consistent with NF derivation
            let rho32 = {
                let h = blake3::hash(&cmx32);
                let mut out = [0u8; 32];
                out.copy_from_slice(h.as_bytes());
                out
            };

            // Choose a value commitment cv deterministically (canonical field encoding)
            let cv32 = to_canonical_fr_bytes(&{
                let mut buf = Vec::with_capacity(32 + 32 + 8);
                buf.extend_from_slice(&cmx32);
                buf.extend_from_slice(&state.mmr_root);
                buf.extend_from_slice(&state.nullifier_root);
                buf
            });

            // EPK placeholder: canonical field encoding derived from (cmx || i)
            let epk32 = to_canonical_fr_bytes(&{
                let mut buf = vec![0u8; 4];
                buf[..4].copy_from_slice(&(i as u32).to_le_bytes());
                let mut all = Vec::with_capacity(36);
                all.extend_from_slice(&cmx32);
                all.extend_from_slice(&buf);
                all
            });

            // Produce a SpendLink proof binding (state_root, link)
            let (proof_bytes, _sr, link_bytes) = prove_spend_link::<64>(
                12,
                &state.mmr_root,
                &state.nullifier_root,
                &rk_bytes32,
                &snk,
                &rho32,
                &cmx32,
                &cv32,
            )?;

            action_links.push(link_bytes);

            // Aggregate links with state_root to form agg_final (later used in sighash)
            // We'll compute the final aggregation after the loop once we know all links.

            // Fill action (ciphertexts left empty in this prototype)
            actions.push(_node_ext_dep_check::Action {
                cv: cv32,
                nf,
                rk_bytes: rk_bytes32,
                cmx: cmx32,
                epk: epk32,
                proof: proof_bytes,
                spend_auth_sig: Vec::new(), // filled after computing agg_final
                enc_ciphertext: Vec::new(),
                out_ciphertext: Vec::new(),
            });
        }

        // Compute aggregation binding commitment across all actions
        let pairs: Vec<([u8; 32], [u8; 32])> = action_links.iter().map(|l| (state_root, *l)).collect();
        let agg_final = compute_wallet_agg_final_bytes_checked(&pairs)
            .ok_or_else(|| anyhow!("failed to compute wallet agg_final"))?;

        let actions_len = actions.len() as u32;
        // Sign each action digest under SuiteB to populate spend_auth_sig
        for (i, action) in actions.iter_mut().enumerate() {
            let digest32 = SuiteB::blake3_prehash_with_domain(
                b"sighash:orchard:action:v1",
                &[
                    &1u32.to_le_bytes(),
                    &(i as u32).to_le_bytes(),
                    &state.mmr_root,
                    &state.nullifier_root,
                    &agg_final,
                    &actions_len.to_le_bytes(),
                    &action.nf,
                    &action.rk_bytes,
                    &action.cmx,
                    &action.cv,
                    &action.epk,
                    &action.enc_ciphertext,
                    &action.out_ciphertext,
                    &[0u8; 1],
                ],
            );
            let sig = SuiteB::sign_prehash(&suite_sk, &digest32)?;
            action.spend_auth_sig = sig.as_bytes().to_vec();
        }

        let tx = _node_ext_dep_check::Transaction {
            hash: _node_ext_dep_check::TransactionHash(blake3::hash(b"wallet-tx")),
            nullifiers,
            commitments: output_commitments,
            spent_commitments: spent_inputs.clone(),
            membership_witnesses: witnesses,
            pcd_proof,
            pcd_prev_state_commitment: prev_state,
            pcd_new_state_commitment: new_state,
            pcd_mmr_root: state.mmr_root,
            pcd_nullifier_root: state.nullifier_root,
            anchor_height: state.anchor_height,
            spend_proof,
            nullifier_non_membership,
            actions,
        };

        Ok(tx)
    }

    #[cfg(not(feature = "pcd"))]
    pub async fn build_node_transaction(
        &self,
        _spent_inputs: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
        _output_commitments: Vec<[u8; NOTE_COMMITMENT_SIZE]>,
    ) -> Result<()> {
        Err(anyhow!("PCD feature disabled"))
    }

    /// Sync wallet state to latest
    #[cfg(feature = "pcd")]
    pub async fn sync(&self) -> Result<()> {
        let mut sync_manager = self.sync_manager.write().await;
        if let Some(ref mut sync_mgr) = sync_manager.as_mut() {
            let target_height = 1000; // Would get from network
            sync_mgr.sync_to_height(target_height).await?;
        }
        Ok(())
    }

    #[cfg(not(feature = "pcd"))]
    pub async fn sync(&self) -> Result<()> { Ok(()) }

    /// Get current PCD state
    #[cfg(feature = "pcd")]
    pub async fn get_pcd_state(&self) -> Option<PcdState> {
        self.pcd_manager.read().await.current_state().cloned()
    }

    #[cfg(not(feature = "pcd"))]
    pub async fn get_pcd_state(&self) -> Option<()> { None }

    /// Update and persist MMR witnesses for unspent notes after adopting a new PCD state.
    /// Uses the delta update API to avoid full recomputation and only persists changed witnesses.
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

            // Try to load existing witness and apply a delta update
            let mut updated_bytes_opt: Option<Vec<u8>> = None;

            if let Some(existing) = database.get_witness(pos).await {
                if let Ok(old_bytes) = existing.decrypt_witness(&database.master_key) {
                    if let Ok(mut old_witness) = bincode::deserialize::<MmrWitness>(&old_bytes) {
                        if let Ok(update) = mmr.compute_witness_update(pos) {
                            old_witness.apply_update(&update);
                            if let Ok(new_bytes) = bincode::serialize(&old_witness) {
                                if new_bytes != old_bytes { updated_bytes_opt = Some(new_bytes); }
                            }
                        }
                    }
                }
            }

            // If no existing witness or delta path failed, compute a fresh one
            if updated_bytes_opt.is_none() {
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
                    if let Ok(bytes) = bincode::serialize(&witness) {
                        updated_bytes_opt = Some(bytes);
                    }
                }
            }

            if let Some(bytes) = updated_bytes_opt {
                let rec = storage::WitnessRecord::new(pos, &bytes, &database.master_key)?;
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
    pub outputs: Vec<[u8; 32]>,
    /// Spend proofs for input notes
    pub spend_proofs: Vec<Vec<u8>>,
    /// Output proofs for output notes
    pub output_proofs: Vec<Vec<u8>>,
    /// Nullifiers for input notes
    pub nullifiers: Vec<[u8; 32]>,
    /// Anchor height for PCD proof
    pub anchor_height: u64,
    /// PCD proof data
    pub pcd_proof: Vec<u8>,
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
        for o in &self.outputs { h.update(o); }
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
            hasher.update(output);
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
    async fn test_wallet_creation() -> anyhow::Result<()> {
        let config = WalletConfig::default();
        let wallet = TachyonWallet::new(config).await?;

        let stats = wallet.get_stats().await?;
        assert_eq!(stats.db_stats.total_notes, 0);
        assert_eq!(stats.pending_payments, 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_wallet_initialization() -> anyhow::Result<()> {
        #[cfg(not(feature = "pcd"))]
        {
            // If PCD is disabled, initialize() is a no-op and should not fail.
            let mut config = WalletConfig::default();
            config.db_path = tempfile::tempdir()?
                .path()
                .join("test_wallet")
                .to_string_lossy()
                .to_string();
            let mut wallet = TachyonWallet::new(config).await?;
            wallet.initialize().await?;
            return Ok(());
        }
        let mut config = WalletConfig::default();
        config.db_path = tempfile::tempdir()?
            .path()
            .join("test_wallet")
            .to_string_lossy()
            .to_string();

        let mut wallet = TachyonWallet::new(config).await?;
        wallet.initialize().await?;

        #[cfg(feature = "pcd")]
        {
            let pcd_state = wallet.get_pcd_state().await;
            assert!(pcd_state.is_some());
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_oob_payment() -> anyhow::Result<()> {
        #[cfg(not(feature = "pcd"))]
        return Ok(());
        let config = WalletConfig::default();
        let wallet = TachyonWallet::new(config).await?;

        let recipient_pk = wallet.get_oob_public_key().await;
        let note_data = b"test note for payment".to_vec();
        let associated_data = b"payment_context".to_vec();

        let payment = wallet
            .create_oob_payment(recipient_pk, note_data.clone(), associated_data)
            .await
            ?;
        payment.verify()?;

        let payment_hash = wallet.receive_oob_payment(payment).await?;
        assert_eq!(payment_hash.len(), 32);

        let processed_note = wallet.process_oob_payment(&payment_hash).await?;
        assert!(processed_note.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn test_transaction_building() -> anyhow::Result<()> {
        let config = WalletConfig::default();
        let wallet = TachyonWallet::new(config).await?;

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
            ?;
        assert_eq!(transaction.outputs.len(), 1);
        assert_eq!(transaction.inputs.len(), 0);
        Ok(())
    }
}
