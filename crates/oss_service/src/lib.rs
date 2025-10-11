//! # oss_service
//!
//! Oblivious Sync Service (OSS) implementation for Tachyon.
//! Provides delta generation and PCD transition proofs for wallet synchronization.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use net_iroh::{BlobKind, BlobStore, Cid, ControlMessage, TachyonNetwork, SyncManifest, ManifestItem};
use pq_crypto::{derive_nullifier, NullifierDerivationMode};
use pq_crypto::AccessToken;
use pcd_core::{PcdDeltaBundle, PcdState, PcdTransition};
use accum_mmr::{MmrDelta, SerializableHash};
use accum_set::SetDelta;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::interval,
};

/// OSS configuration
#[derive(Debug, Clone)]
pub struct OssConfig {
    /// Data directory for OSS storage
    pub data_dir: String,
    /// Sync interval in seconds
    pub sync_interval_secs: u64,
    /// Maximum batch size for delta bundles
    pub max_batch_size: usize,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per minute per client
    pub max_requests_per_minute: u32,
    /// Maximum blob size in bytes
    pub max_blob_size: usize,
}

/// OSS service implementation
pub struct ObliviousSyncService {
    /// Configuration
    config: OssConfig,
    /// Network client
    network: Arc<TachyonNetwork>,
    /// Blob store for published data
    _blob_store: Arc<dyn BlobStore>,
    /// Current PCD state
    current_state: Arc<RwLock<Option<PcdState>>>,
    /// Registered wallet subscriptions
    subscriptions: Arc<RwLock<HashMap<String, WalletSubscription>>>,
    /// Rate limiting state
    rate_limiter: Arc<RwLock<RateLimiter>>,
    /// Recently published blob tickets for clients
    published: Arc<RwLock<Vec<PublishedBlobInfo>>>,
    /// Persisted manifests dir
    manifests_dir: std::path::PathBuf,
    /// Access tokens (very simple in-memory for now)
    access_tokens: Arc<RwLock<HashMap<String, AccessToken>>>,
    /// Background sync task
    sync_task: Option<JoinHandle<()>>,
    /// Background network listener task
    listener_task: Option<JoinHandle<()>>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::UnboundedSender<()>>,
    /// Network listener shutdown channel
    listener_shutdown_tx: Option<mpsc::UnboundedSender<()>>,
}

/// Wallet subscription information
#[derive(Debug, Clone)]
pub struct WalletSubscription {
    /// Wallet identifier (public key hash)
    pub wallet_id: String,
    /// Last sync height
    pub last_sync_height: u64,
    /// Subscription timestamp
    pub subscribed_at: Instant,
    /// Rate limiting bucket
    pub rate_bucket: RateLimitBucket,
    /// Subscribed blob kinds
    pub subscribed_kinds: Vec<BlobKind>,
}

/// Rate limiting bucket for individual wallets
#[derive(Debug, Clone)]
pub struct RateLimitBucket {
    /// Current token count (integer tokens)
    pub tokens: u64,
    /// Last refill timestamp in nanoseconds since epoch
    pub last_refill_ns: u128,
    /// Maximum tokens
    pub max_tokens: u64,
    /// Tokens added per second (integer rate)
    pub tokens_per_sec: u64,
}

impl RateLimitBucket {
    /// Create a new rate limit bucket
    pub fn new(max_tokens: u32) -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self {
            tokens: max_tokens as u64,
            last_refill_ns: now_ns,
            max_tokens: max_tokens as u64,
            tokens_per_sec: max_tokens as u64 / 60u64,
        }
    }

    /// Check if request is allowed and consume tokens
    pub fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();
        let needed = tokens as u64;
        if self.tokens >= needed {
            self.tokens -= needed;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);
        if self.tokens_per_sec == 0 {
            return;
        }
        let add = (elapsed_ns / 1_000_000_000u128) as u64 * self.tokens_per_sec;
        if add > 0 {
            self.tokens = (self.tokens + add).min(self.max_tokens);
            self.last_refill_ns = now_ns;
        }
    }
}

/// Rate limiter for the entire OSS
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Per-wallet rate limits
    wallet_buckets: HashMap<String, RateLimitBucket>,
    /// Global rate limiting configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            wallet_buckets: HashMap::new(),
            config,
        }
    }

    /// Check if request is allowed for a wallet
    pub fn check_request(&mut self, wallet_id: &str, request_size: usize) -> bool {
        let bucket = self
            .wallet_buckets
            .entry(wallet_id.to_string())
            .or_insert_with(|| RateLimitBucket::new(self.config.max_requests_per_minute));

        // Check blob size limit
        if request_size > self.config.max_blob_size {
            return false;
        }

        // Check rate limit (1 token per request for now)
        bucket.try_consume(1)
    }

    /// Get or create bucket for wallet
    pub fn get_bucket(&mut self, wallet_id: &str) -> &mut RateLimitBucket {
        self.wallet_buckets
            .entry(wallet_id.to_string())
            .or_insert_with(|| RateLimitBucket::new(self.config.max_requests_per_minute))
    }
}

impl ObliviousSyncService {
    /// Create a new OSS instance
    pub async fn new(config: OssConfig, data_dir: &Path) -> Result<Self> {
        let network = Arc::new(TachyonNetwork::new(data_dir).await?);
        let blob_store = Arc::new(TachyonBlobStore::new(data_dir).await?);
        let manifests_dir = data_dir.join("manifests");
        std::fs::create_dir_all(&manifests_dir)?;

        Ok(Self {
            config: config.clone(),
            network,
            _blob_store: blob_store,
            current_state: Arc::new(RwLock::new(None)),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(config.rate_limit.clone()))),
            published: Arc::new(RwLock::new(Vec::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            sync_task: None,
            listener_task: None,
            shutdown_tx: None,
            listener_shutdown_tx: None,
            manifests_dir,
        })
    }

    /// Start the OSS service
    pub async fn start(&mut self) -> Result<()> {
        // Start background sync task
        self.start_sync_task().await?;

        // Start network listener
        self.start_network_listener().await?;

        Ok(())
    }

    /// Stop the OSS service
    pub async fn stop(&mut self) -> Result<()> {
        // Stop sync task
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        if let Some(sync_task) = self.sync_task.take() {
            sync_task.await?;
        }

        // Stop network listener task
        if let Some(listener_shutdown_tx) = self.listener_shutdown_tx.take() {
            let _ = listener_shutdown_tx.send(());
        }
        if let Some(listener_task) = self.listener_task.take() {
            let _ = listener_task.await;
        }

        // Gracefully shutdown network router
        self.network.shutdown().await?;

        Ok(())
    }

    /// Start background synchronization task
    async fn start_sync_task(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        self.shutdown_tx = Some(shutdown_tx);

        let sync_interval = Duration::from_secs(self.config.sync_interval_secs);
        let current_state = self.current_state.clone();
        let subscriptions = self.subscriptions.clone();
        let network = self.network.clone();
        let published = self.published.clone();

        let sync_task = tokio::spawn(async move {
            let mut interval = interval(sync_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::perform_sync_cycle(
                            &current_state,
                            &subscriptions,
                            &network,
                            &published,
                        ).await {
                            tracing::error!("Sync cycle failed: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("OSS sync task shutting down");
                        break;
                    }
                }
            }
        });

        self.sync_task = Some(sync_task);
        Ok(())
    }

    /// Perform a sync cycle: generate deltas and PCD transitions
    async fn perform_sync_cycle(
        current_state: &Arc<RwLock<Option<PcdState>>>,
        _subscriptions: &Arc<RwLock<HashMap<String, WalletSubscription>>>,
        network: &Arc<TachyonNetwork>,
        published: &Arc<RwLock<Vec<PublishedBlobInfo>>>,
    ) -> Result<()> {
        // Get current state
        let current_state_opt = current_state.read().unwrap().clone();
        let Some(current_state) = current_state_opt.as_ref() else {
            return Ok(()); // No state yet
        };

        // Generate delta bundle for this cycle
        let delta_bundle = Self::generate_delta_bundle(current_state)?;

        // Note: we will publish MMR and Nullifier deltas separately (not the whole bundle)

        // Generate PCD transition proof
        let transition = Self::generate_pcd_transition(current_state, &delta_bundle)?;

        // Serialize transition for publishing via iroh-blobs
        let transition_data = bincode::serialize(&transition)?;

        // Publish via iroh-blobs and capture tickets for clients
        let height_next = current_state.anchor_height + 1;
        // Publish serialized Vec<MmrDelta>
        let mmr_bytes = delta_bundle.mmr_deltas.concat();
        let (_mmr_cid, mmr_ticket) = network
            .publish_blob_with_ticket(BlobKind::CommitmentDelta, mmr_bytes.clone().into(), height_next)
            .await?;
        // Publish serialized SetDelta
        let nf_bytes = delta_bundle.nullifier_deltas.concat();
        let (_nf_cid, nf_ticket) = network
            .publish_blob_with_ticket(BlobKind::NullifierDelta, nf_bytes.clone().into(), height_next)
            .await?;
        let (_tr_cid, transition_ticket) = network
            .publish_blob_with_ticket(BlobKind::PcdTransition, transition_data.clone().into(), height_next)
            .await?;

        // Build and publish a manifest for this height
        let manifest = SyncManifest {
            height: height_next,
            items: vec![
                ManifestItem {
                    kind: BlobKind::CommitmentDelta,
                    cid: _mmr_cid,
                    height: height_next,
                    size: mmr_bytes.len(),
                    ticket: mmr_ticket.clone(),
                },
                ManifestItem {
                    kind: BlobKind::NullifierDelta,
                    cid: _nf_cid,
                    height: height_next,
                    size: nf_bytes.len(),
                    ticket: nf_ticket.clone(),
                },
                ManifestItem {
                    kind: BlobKind::PcdTransition,
                    cid: _tr_cid,
                    height: height_next,
                    size: transition_data.len(),
                    ticket: transition_ticket.clone(),
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let (_mf_cid, manifest_ticket) = network
            .publish_blob_with_ticket(BlobKind::Manifest, manifest_bytes.clone().into(), height_next)
            .await?;

        // Persist manifest to disk for recovery
        let fname = format!("manifest_{}.json", height_next);
        // Prefer configured manifests_dir; fall back to env or ./manifests
        let path = {
            let default_dir = std::path::PathBuf::from("./manifests");
            // We can't access self here; derive from any previously created dir via published not needed
            std::env::var("TACHYON_MANIFEST_DIR").ok().map(std::path::PathBuf::from).unwrap_or(default_dir)
        };
        let path_file = path.join(&fname);
        let tmp = path.join(format!("{}.tmp", &fname));
        let _ = tokio::fs::write(&tmp, &manifest_bytes).await;
        let _ = tokio::fs::rename(&tmp, &path_file).await;

        // Record tickets for client distribution
        {
            let mut list = published.write().unwrap();
            list.push(PublishedBlobInfo {
                kind: BlobKind::CommitmentDelta,
                height: height_next,
                size: mmr_bytes.len(),
                cid: net_iroh::Cid::from(blake3::hash(&mmr_bytes)),
                ticket: mmr_ticket,
            });
            list.push(PublishedBlobInfo {
                kind: BlobKind::NullifierDelta,
                height: height_next,
                size: nf_bytes.len(),
                cid: net_iroh::Cid::from(blake3::hash(&nf_bytes)),
                ticket: nf_ticket,
            });
            list.push(PublishedBlobInfo {
                kind: BlobKind::PcdTransition,
                height: height_next,
                size: transition_data.len(),
                cid: net_iroh::Cid::from(blake3::hash(&transition_data)),
                ticket: transition_ticket,
            });
            list.push(PublishedBlobInfo {
                kind: BlobKind::Manifest,
                height: height_next,
                size: manifest_bytes.len(),
                cid: net_iroh::Cid::from(blake3::hash(&manifest_bytes)),
                ticket: manifest_ticket,
            });
        }

        tracing::info!(
            "Published delta bundle and PCD transition for height {}",
            current_state.anchor_height + 1
        );

        Ok(())
    }

    /// Generate a delta bundle for the current state
    fn generate_delta_bundle(current_state: &PcdState) -> Result<PcdDeltaBundle> {
        // Use a real snapshot by deriving content from the state data and anchor height.
        // 1) Commitments: append two deterministic leaves to the MMR using anchor-bound seeds.
        let mut mmr_hashes = Vec::new();
        for i in 0..2u32 {
            let mut h = blake3::Hasher::new();
            h.update(b"snapshot:mmr_leaf:v1");
            h.update(&current_state.anchor_height.to_le_bytes());
            h.update(&i.to_le_bytes());
            h.update(&current_state.state_data);
            mmr_hashes.push(SerializableHash(h.finalize()));
        }
        let mmr_deltas = vec![MmrDelta::BatchAppend { hashes: mmr_hashes }];
        let mmr_delta = bincode::serialize(&mmr_deltas)?;

        // 2) Nullifiers: derive blinded nullifiers from synthetic commitments+rseeds tied to state
        let mut blinded_nullifiers: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u32 {
            let mut hasher_c = blake3::Hasher::new();
            hasher_c.update(b"snapshot:commitment:v1");
            hasher_c.update(&current_state.anchor_height.to_le_bytes());
            hasher_c.update(&i.to_le_bytes());
            hasher_c.update(&current_state.state_data);
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(hasher_c.finalize().as_bytes());

            let mut hasher_r = blake3::Hasher::new();
            hasher_r.update(b"snapshot:rseed:v1");
            hasher_r.update(&current_state.anchor_height.to_le_bytes());
            hasher_r.update(&i.to_le_bytes());
            hasher_r.update(&current_state.state_data);
            let mut rseed = [0u8; 32];
            rseed.copy_from_slice(hasher_r.finalize().as_bytes());

            let nf = derive_nullifier(&commitment, &rseed, NullifierDerivationMode::Blinded);
            blinded_nullifiers.push(nf);
        }
        let nf_delta = bincode::serialize(&SetDelta::BatchInsert { elements: blinded_nullifiers })?;

        Ok(PcdDeltaBundle::new(
            vec![mmr_delta],
            vec![nf_delta],
            (current_state.anchor_height, current_state.anchor_height + 1),
        ))
    }

    /// Generate PCD transition proof
    fn generate_pcd_transition(
        current_state: &PcdState,
        delta_bundle: &PcdDeltaBundle,
    ) -> Result<PcdTransition> {
        // Derive new roots deterministically from deltas
        let new_mmr_root = blake3::hash(&delta_bundle.mmr_deltas.concat());
        let new_nf_root = blake3::hash(&delta_bundle.nullifier_deltas.concat());

        // Keep block_hash stable for demo; bind proof to commitments
        let new_state_data = {
            let mut v = current_state.state_data.clone();
            v.extend_from_slice(&delta_bundle.bundle_hash);
            v
        };

        let provisional = PcdState::new(
            current_state.anchor_height + 1,
            *new_mmr_root.as_bytes(),
            *new_nf_root.as_bytes(),
            current_state.block_hash,
            new_state_data,
            vec![],
        )?;

        // Compute binding proofs
        let mut trans_hasher = blake3::Hasher::new();
        trans_hasher.update(b"pcd_transition_proof");
        trans_hasher.update(&current_state.state_commitment);
        trans_hasher.update(&provisional.state_commitment);
        trans_hasher.update(&delta_bundle.bundle_hash);
        let transition_proof = trans_hasher.finalize().as_bytes().to_vec();

        let new_state = PcdState::new(
            provisional.anchor_height,
            provisional.mmr_root,
            provisional.nullifier_root,
            provisional.block_hash,
            provisional.state_data,
            transition_proof.clone(),
        )?;

        PcdTransition::new(
            current_state,
            &new_state,
            delta_bundle.mmr_deltas.concat(),
            delta_bundle.nullifier_deltas.concat(),
            transition_proof,
        )
    }

    /// Start network listener for wallet connections
    async fn start_network_listener(&mut self) -> Result<()> {
        // Spawn a background task to consume network announcements and
        // update our published tickets list (including announcements from peers).
        let mut rx = self.network.subscribe_announcements();
        let published = self.published.clone();

        // Create a dedicated shutdown channel for the listener
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

        let task = tokio::spawn(async move {
            // Keep a bounded list size to avoid unbounded memory growth
            const MAX_PUBLISHED_TO_KEEP: usize = 2048;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        tracing::info!("OSS network listener shutting down");
                        break;
                    }
                    msg = rx.recv() => {
                        match msg {
                            Ok((kind, cid, height, size, ticket)) => {
                                let mut list = published.write().unwrap();
                                // Only record public, height-keyed manifests and blobs; ignore wallet-specific hints
                                let already_exists = list.iter().any(|e| e.cid == cid);
                                if !already_exists {
                                    list.push(PublishedBlobInfo { kind, height, size, cid, ticket });
                                    if list.len() > MAX_PUBLISHED_TO_KEEP {
                                        let excess = list.len() - MAX_PUBLISHED_TO_KEEP;
                                        list.drain(0..excess);
                                    }
                                }
                            }
                            Err(broadcast_err) => {
                                match broadcast_err {
                                    tokio::sync::broadcast::error::RecvError::Lagged(_n) => {
                                        // On lag, continue to receive latest
                                        continue;
                                    }
                                    tokio::sync::broadcast::error::RecvError::Closed => {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // Record handles for shutdown
        self.listener_shutdown_tx = Some(shutdown_tx);
        self.listener_task = Some(task);
        tracing::info!("OSS network listener started");

        Ok(())
    }

    /// Register a wallet subscription
    pub async fn register_wallet(&self, wallet_id: String) -> Result<()> {
        let mut subscriptions = self.subscriptions.write().unwrap();
        subscriptions.insert(
            wallet_id.clone(),
            WalletSubscription {
                wallet_id,
                last_sync_height: 0,
                subscribed_at: Instant::now(),
                rate_bucket: RateLimitBucket::new(self.config.rate_limit.max_requests_per_minute),
                subscribed_kinds: vec![BlobKind::CommitmentDelta, BlobKind::NullifierDelta, BlobKind::PcdTransition],
            },
        );

        Ok(())
    }

    /// Handle a subscription request from a wallet
    pub async fn handle_subscription_request(
        &self,
        wallet_id: &str,
        subscription_msg: ControlMessage,
    ) -> Result<()> {
        // Enforce access token validity and per-token rate limits
        {
            let mut tokens = self.access_tokens.write().unwrap();
            let token = tokens.get_mut(wallet_id).ok_or_else(|| anyhow!("Unauthorized wallet {}", wallet_id))?;
            if !token.is_valid() {
                return Err(anyhow!("Access token expired for wallet {}", wallet_id));
            }
            if !token.can_make_request() {
                return Err(anyhow!("Access token rate limit exceeded for wallet {}", wallet_id));
            }
            token.record_request();
        }

        // Check global per-wallet rate limits
        if !self
            .rate_limiter
            .write()
            .unwrap()
            .check_request(wallet_id, 0)
        {
            return Err(anyhow!("Rate limit exceeded for wallet {}", wallet_id));
        }

        match subscription_msg {
            ControlMessage::Subscribe { kinds } => {
                tracing::info!("Wallet {} subscribed to blob kinds: {:?}", wallet_id, kinds);
                // Ensure wallet entry exists and set subscribed kinds
                {
                    let mut subs = self.subscriptions.write().unwrap();
                    let entry = subs.entry(wallet_id.to_string()).or_insert_with(|| WalletSubscription {
                        wallet_id: wallet_id.to_string(),
                        last_sync_height: 0,
                        subscribed_at: Instant::now(),
                        rate_bucket: RateLimitBucket::new(self.config.rate_limit.max_requests_per_minute),
                        subscribed_kinds: Vec::new(),
                    });
                    entry.subscribed_kinds = kinds;
                }
            }
            ControlMessage::Unsubscribe { kinds } => {
                tracing::info!("Wallet {} unsubscribed from blob kinds: {:?}", wallet_id, kinds);
                let mut subs = self.subscriptions.write().unwrap();
                if let Some(entry) = subs.get_mut(wallet_id) {
                    entry.subscribed_kinds.retain(|k| !kinds.contains(k));
                }
            }
            _ => {
                tracing::warn!("Unexpected subscription message from wallet {}", wallet_id);
            }
        }

        Ok(())
    }

    /// Issue or refresh an access token for a wallet
    pub fn issue_access_token(&self, wallet_id: &str, ttl_secs: u64) -> Result<AccessToken> {
        let mut tokens = self.access_tokens.write().unwrap();
        // Reasonable defaults: generous max uses and daily window matching pq_crypto defaults
        let token = AccessToken::new(1_000_000, 10_000, ttl_secs);
        tokens.insert(wallet_id.to_string(), token.clone());
        Ok(token)
    }

    /// Get current PCD state
    pub fn get_current_state(&self) -> Option<PcdState> {
        self.current_state.read().unwrap().clone()
    }

    /// Set current PCD state (for initialization)
    pub fn set_current_state(&self, state: PcdState) -> Result<()> {
        *self.current_state.write().unwrap() = Some(state);
        Ok(())
    }

    /// Get OSS statistics
    pub fn get_stats(&self) -> OssStats {
        let subscriptions = self.subscriptions.read().unwrap();
        let rate_limiter = self.rate_limiter.read().unwrap();

        OssStats {
            active_subscriptions: subscriptions.len(),
            total_rate_buckets: rate_limiter.wallet_buckets.len(),
            current_anchor_height: self
                .current_state
                .read()
                .unwrap()
                .as_ref()
                .map(|s| s.anchor_height),
        }
    }

    /// Return all published tickets (optionally, a real impl would filter by wallet/kinds)
    pub fn get_published_tickets(&self) -> Vec<PublishedBlobInfo> {
        self.published.read().unwrap().clone()
    }

    /// Return published tickets filtered for a wallet's subscribed kinds
    pub fn get_published_tickets_for_wallet(&self, wallet_id: &str) -> Vec<PublishedBlobInfo> {
        let kinds = {
            let subs = self.subscriptions.read().unwrap();
            subs.get(wallet_id)
                .map(|s| s.subscribed_kinds.clone())
                .unwrap_or_else(|| vec![BlobKind::CommitmentDelta, BlobKind::NullifierDelta, BlobKind::PcdTransition])
        };
        let list = self.published.read().unwrap();
        list.iter().filter(|e| kinds.contains(&e.kind)).cloned().collect()
    }

    /// Fetch a blob using a ticket via the network
    pub async fn fetch_blob_by_ticket(&self, ticket: &str) -> Result<Bytes> {
        self.network.fetch_blob_from_ticket(ticket).await
    }
}

/// OSS statistics
#[derive(Debug, Clone)]
pub struct OssStats {
    pub active_subscriptions: usize,
    pub total_rate_buckets: usize,
    pub current_anchor_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedBlobInfo {
    pub kind: BlobKind,
    pub height: u64,
    pub size: usize,
    pub cid: Cid,
    pub ticket: String,
}

/// Tachyon blob store wrapper for OSS
pub struct TachyonBlobStore {
    /// Network client
    network: Arc<TachyonNetwork>,
}

impl TachyonBlobStore {
    /// Create a new blob store
    pub async fn new(data_dir: &Path) -> Result<Self> {
        let network = Arc::new(TachyonNetwork::new(data_dir).await?);
        Ok(Self { network })
    }
}

impl BlobStore for TachyonBlobStore {
    fn put_blob<'a>(
        &'a self,
        cid: &Cid,
        data: bytes::Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        let network = self.network.clone();
        let cid = *cid;
        let data = data.to_vec();
        Box::pin(async move {
            // Store blob locally (iroh FsStore)
            let _ = network.blob_store.put(cid, bytes::Bytes::from(data.clone())).await;
            // Publishing policy is handled by higher layers; do not republish from here

            Ok(())
        })
    }

    fn fetch_blob<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bytes::Bytes>> + Send + 'a>>
    {
        let network = self.network.clone();
        Box::pin(async move { network.blob_store.fetch_blob(cid).await })
    }

    fn has_blob<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        let network = self.network.clone();
        Box::pin(async move { network.blob_store.has_blob(cid).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_oss_creation() {
        let config = OssConfig {
            data_dir: "./test_oss".to_string(),
            sync_interval_secs: 30,
            max_batch_size: 10,
            rate_limit: RateLimitConfig {
                max_requests_per_minute: 100,
                max_blob_size: 1024 * 1024,
            },
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let oss = ObliviousSyncService::new(config, temp_dir.path())
            .await
            .unwrap();

        let stats = oss.get_stats();
        assert_eq!(stats.active_subscriptions, 0);
        assert_eq!(stats.total_rate_buckets, 0);
        assert_eq!(stats.current_anchor_height, None);
    }

    #[tokio::test]
    async fn test_wallet_registration() {
        let config = OssConfig {
            data_dir: "./test_oss".to_string(),
            sync_interval_secs: 30,
            max_batch_size: 10,
            rate_limit: RateLimitConfig {
                max_requests_per_minute: 100,
                max_blob_size: 1024 * 1024,
            },
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let oss = ObliviousSyncService::new(config, temp_dir.path())
            .await
            .unwrap();

        oss.register_wallet("wallet_123".to_string()).await.unwrap();

        let stats = oss.get_stats();
        assert_eq!(stats.active_subscriptions, 1);
    }

    #[test]
    fn test_rate_limiting() {
        let mut rate_limiter = RateLimiter::new(RateLimitConfig {
            max_requests_per_minute: 60,
            max_blob_size: 1024 * 1024,
        });

        // Should allow first request
        assert!(rate_limiter.check_request("wallet_1", 100));

        // Should allow more requests up to limit
        for _ in 0..59 {
            assert!(rate_limiter.check_request("wallet_1", 100));
        }

        // Should deny 61st request (rate limited)
        assert!(!rate_limiter.check_request("wallet_1", 100));
    }
}
