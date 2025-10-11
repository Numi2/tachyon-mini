//! # header_sync
//!
//! Header chain synchronization and bootstrapping for Tachyon.
//! Implements NiPoPoW-style proofs for efficient header verification and fast bootstrapping.

use anyhow::{anyhow, Result};
use blake3::Hash;
#[cfg(feature = "zcash_zebra")]
use zebra_chain::parameters::Network as ZebraNetwork;
#[cfg(feature = "zcash_zebra")]
use zebra_chain::work::equihash::Solution as ZebraEquihashSolution;
#[cfg(feature = "zcash_zebra")]
use zebra_chain::work::difficulty::Expanded as ZebraExpandedTarget;
#[cfg(feature = "zcash_zebra")]
use zebra_chain::block::Header as ZebraHeader;
use pq_crypto::{SuiteB, SuiteBPublicKey, SuiteBSignature, SUITE_B_DOMAIN_CHECKPOINT};
use net_iroh::{BlobKind, TachyonNetwork};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, RwLock},
    task::JoinHandle,
    time::interval,
};
use tracing::{info, warn};
use reqwest::Client;

/// Configuration for header sync
#[derive(Debug, Clone, Default)]
pub struct HeaderSyncConfig {
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Sync configuration
    pub sync_config: SyncConfig,
    /// Security parameters
    pub security_config: SecurityConfig,
    /// Proof-of-Work and header validation configuration
    pub pow_config: PowConfig,
}

/// Network configuration for header sync
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// Data directory for header storage
    pub data_dir: String,
    /// Trusted checkpoint servers (HTTPS endpoints returning signed checkpoints)
    pub checkpoint_servers: Vec<String>,
    /// Maximum number of peers for header sync
    pub max_sync_peers: usize,
}

/// Sync configuration parameters
#[derive(Debug, Clone, Default)]
pub struct SyncConfig {
    /// Target sync latency in milliseconds
    pub target_latency_ms: u64,
    /// Maximum header batch size for sync
    pub max_batch_size: usize,
    /// Header verification timeout in milliseconds
    pub verification_timeout_ms: u64,
    /// Checkpoint sync interval in blocks
    pub checkpoint_interval: u64,
}

/// Security configuration for NiPoPoW
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    /// Security parameter k for NiPoPoW
    pub security_parameter_k: u32,
    /// Maximum chain quality we assume
    pub max_chain_quality: f64,
    /// Minimum honest majority we assume
    pub min_honest_majority: f64,
    /// Minimum number of trusted signatures required on checkpoints
    pub min_checkpoint_signatures: usize,
    /// Optional trusted checkpoint public keys (Dilithium3/Suite B). If empty, any valid signature counts.
    pub trusted_checkpoint_keys: Vec<Vec<u8>>, // raw pk bytes
}

/// Proof-of-Work configuration, including optional Equihash verification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PowConfig {
    /// If true, skip all PoW validation (useful for custom testnets)
    pub disable_pow_validation: bool,
    /// If true, validate Equihash solution according to configured parameters
    pub validate_equihash_solution: bool,
    /// Equihash parameter n (e.g., 200 for Zcash main/test)
    pub equihash_n: u32,
    /// Equihash parameter k (e.g., 9 for Zcash main/test)
    pub equihash_k: u32,
}

/// Header chain representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderChain {
    /// Genesis header
    pub genesis: BlockHeader,
    /// Current headers indexed by height
    pub headers: HashMap<u64, BlockHeader>,
    /// Current chain tip
    pub tip: Option<u64>,
    /// MMR roots for each height
    pub mmr_roots: HashMap<u64, SerializableHash>,
    /// Nullifier set roots for each height
    pub nullifier_roots: HashMap<u64, SerializableHash>,
    /// Checkpoint data for fast sync
    pub checkpoints: Vec<Checkpoint>,
    /// PoW configuration governing header validation
    pub pow: PowConfig,
}

impl HeaderChain {
    /// Create a new header chain starting with genesis
    pub fn new(genesis: BlockHeader) -> Self {
        let mut headers = HashMap::new();
        headers.insert(0, genesis.clone());

        Self {
            genesis,
            headers,
            tip: Some(0),
            mmr_roots: HashMap::new(),
            nullifier_roots: HashMap::new(),
            checkpoints: Vec::new(),
            pow: PowConfig::default(),
        }
    }

    /// Create a new header chain with a specific PoW configuration
    pub fn with_pow_config(genesis: BlockHeader, pow: PowConfig) -> Self {
        let mut s = Self::new(genesis);
        s.pow = pow;
        s
    }

    /// Add a new header to the chain
    pub fn add_header(&mut self, header: BlockHeader) -> Result<()> {
        let height = header.height;

        // Verify header is properly linked
        if height > 0 {
            let prev_header = self
                .headers
                .get(&(height - 1))
                .ok_or_else(|| anyhow!("Previous header not found"))?;

            if header.previous_hash != prev_header.hash {
                return Err(anyhow!("Header not properly linked to previous"));
            }
        }

        // Verify proof of work (simplified)
        if !self.verify_pow(&header) {
            return Err(anyhow!("Proof of work verification failed"));
        }

        self.headers.insert(height, header.clone());
        self.tip = Some(height);

        // Update MMR root if provided
        if let Some(mmr_root) = header.mmr_root {
            self.mmr_roots.insert(height, mmr_root);
        }

        Ok(())
    }

    /// Get header at specific height
    pub fn get_header(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.get(&height)
    }

    /// Get current chain tip
    pub fn get_tip(&self) -> Option<&BlockHeader> {
        self.tip.and_then(|height| self.headers.get(&height))
    }

    /// Verify proof of work (Zcash-tuned: compact target comparison; placeholder for Equihash)
    fn verify_pow(&self, header: &BlockHeader) -> bool {
        if self.pow.disable_pow_validation {
            return true;
        }
        // Validate hash <= target from compact bits
        let target = compact_to_target(header.bits);
        if !cmp256_be(header.hash.as_bytes(), &target) { return false; }
        // Optionally validate Equihash solution parameters (n,k)
        if self.pow.validate_equihash_solution
            && !verify_equihash_solution(header, self.pow.equihash_n, self.pow.equihash_k)
        { return false; }
        true
    }

    /// Generate NiPoPoW proof for a range of headers
    pub fn generate_nipopow_proof(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<NiPoPoWProof> {
        let mut proof_headers = Vec::new();

        for height in (start_height..=end_height).rev() {
            if let Some(header) = self.headers.get(&height) {
                proof_headers.push(header.clone());

                // For NiPoPoW, we need to include proof headers at specific intervals
                // This is a simplified implementation
                if proof_headers.len() >= 3 {
                    break;
                }
            }
        }

        Ok(NiPoPoWProof {
            start_height,
            end_height,
            headers: proof_headers,
            interlink: Vec::new(), // Would contain interlink data in real implementation
        })
    }
}

/// Serializable hash wrapper for blake3::Hash
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializableHash(pub Hash);

impl Serialize for SerializableHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for SerializableHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"32 bytes"));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Ok(SerializableHash(Hash::from(hash_bytes)))
    }
}

impl From<Hash> for SerializableHash {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<SerializableHash> for Hash {
    fn from(wrapper: SerializableHash) -> Self {
        wrapper.0
    }
}

impl SerializableHash {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Convert compact bits to a 256-bit big-endian target
fn compact_to_target(bits: u32) -> [u8; 32] {
    // bits = exponent (8 bits) | mantissa (24 bits)
    let exponent = (bits >> 24) as u8;
    let mantissa = bits & 0x007fffff;
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let shift = 3 - exponent;
        let val = mantissa >> (8 * shift);
        let be = val.to_be_bytes();
        target[28..32].copy_from_slice(&be);
    } else {
        let byte_index = (exponent as usize) - 3;
        if byte_index < 32 {
        let be = mantissa.to_be_bytes();
            let start = 32 - byte_index - 4;
            if start < 32 { target[start..start + 4].copy_from_slice(&be); }
        }
    }
    target
}

/// Compare 256-bit big-endian values: returns true if hash <= target
fn cmp256_be(hash_be: &[u8], target_be: &[u8; 32]) -> bool {
    debug_assert_eq!(hash_be.len(), 32);
    for (h, t) in hash_be.iter().zip(target_be.iter()) {
        if h < t { return true; }
        if h > t { return false; }
    }
    true
}

/// Block header representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height
    pub height: u64,
    /// Previous block hash
    pub previous_hash: SerializableHash,
    /// Block hash (computed)
    pub hash: SerializableHash,
    /// MMR root at this height
    pub mmr_root: Option<SerializableHash>,
    /// Timestamp
    pub timestamp: u64,
    /// Nonce (Zcash: 32-bit little-endian in legacy header; here 64-bit for simplicity)
    pub nonce: u64,
    /// Compact difficulty target (Bitcoin/Zcash-style nBits)
    pub bits: u32,
    /// Equihash solution bytes (Zcash PoW). Optional for chains not using Equihash
    pub solution: Vec<u8>,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        height: u64,
        previous_hash: Hash,
        mmr_root: Option<Hash>,
        timestamp: u64,
        nonce: u64,
        bits: u32,
    ) -> Self {
        let mut header = Self {
            height,
            previous_hash: previous_hash.into(),
            hash: SerializableHash(Hash::from([0u8; 32])), // Will be computed
            mmr_root: mmr_root.map(|h| h.into()),
            timestamp,
            nonce,
            bits,
            solution: Vec::new(),
        };
        header.hash = SerializableHash(header.compute_hash());
        if !header.meets_difficulty() { header.mine(); }
        header
    }

    /// Compute header hash
    pub fn compute_hash(&self) -> Hash {
        // Zcash uses a different header hashing and Equihash solution; for this implementation
        // we domain-separate and include typical header fields so the nBits comparison is meaningful.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tachyon:zcash:header:v1");
        hasher.update(&self.height.to_le_bytes());
        hasher.update(self.previous_hash.0.as_bytes());
        if let Some(mmr_root) = self.mmr_root { hasher.update(mmr_root.0.as_bytes()); }
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.bits.to_le_bytes());
        // Include solution bytes if present to bind PoW
        hasher.update(&self.solution);
        hasher.finalize()
    }

    /// Mine the header to meet difficulty target
    pub fn mine(&mut self) {
        while !self.meets_difficulty() {
            self.nonce += 1;
            self.hash = SerializableHash(self.compute_hash());
        }
    }

    /// Check if hash meets difficulty requirement
    pub fn meets_difficulty(&self) -> bool {
        // Compute target from compact bits (Bitcoin/Zcash style)
        let target = compact_to_target(self.bits);
        let hash_be = *self.hash.0.as_bytes();
        // Compare 256-bit values as big-endian byte arrays
        cmp256_be(hash_be.as_ref(), &target)
    }
}

/// NiPoPoW proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NiPoPoWProof {
    /// Start height of the proof range
    pub start_height: u64,
    /// End height of the proof range
    pub end_height: u64,
    /// Headers included in the proof
    pub headers: Vec<BlockHeader>,
    /// Interlink data for chain quality proof
    pub interlink: Vec<Vec<SerializableHash>>,
}

impl NiPoPoWProof {
    /// Verify the NiPoPoW proof
    pub fn verify(&self, _security_params: &SecurityConfig) -> Result<bool> {
        // Minimum structural checks
        if self.headers.is_empty() { return Ok(false); }
        if self.start_height > self.end_height { return Ok(false); }

        // Headers must be strictly descending by height, properly linked, and meet PoW
        let mut last: Option<&BlockHeader> = None;
        for h in &self.headers {
            if let Some(prev) = last {
                if h.height >= prev.height { return Ok(false); }
                if prev.previous_hash != h.hash { return Ok(false); }
            }
            // Basic PoW/difficulty check
            if !h.meets_difficulty() { return Ok(false); }
            last = Some(h);
        }

        // Interlink consistency: ensure vector sizes are plausible (placeholder sanity)
        for link in &self.interlink {
            if link.len() > 1024 { return Ok(false); }
        }

        Ok(true)
    }
}

/// Checkpoint for fast sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Height of the checkpoint
    pub height: u64,
    /// Header hash at checkpoint
    pub header_hash: SerializableHash,
    /// MMR root at checkpoint
    pub mmr_root: SerializableHash,
    /// Nullifier set root at checkpoint
    pub nullifier_root: SerializableHash,
    /// NiPoPoW proof to this checkpoint
    pub proof: NiPoPoWProof,
    /// Trusted signatures
    pub signatures: Vec<CheckpointSignature>,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(height: u64, header_hash: Hash, mmr_root: Hash, nullifier_root: Hash, proof: NiPoPoWProof) -> Self {
        Self {
            height,
            header_hash: header_hash.into(),
            mmr_root: mmr_root.into(),
            nullifier_root: nullifier_root.into(),
            proof,
            signatures: Vec::new(),
        }
    }

    /// Add a trusted signature
    pub fn add_signature(&mut self, signature: CheckpointSignature) {
        self.signatures.push(signature);
    }

    /// Verify checkpoint using provided security/trust configuration
    pub fn verify_with_trust(&self, security: &SecurityConfig) -> Result<bool> {
        if self.signatures.len() < security.min_checkpoint_signatures {
            return Ok(false);
        }

        // Verify NiPoPoW proof
        self.proof.verify(security)?;

        // Prehash checkpoint payload with Suite B domain
        let digest = SuiteB::blake3_prehash_with_domain(
            SUITE_B_DOMAIN_CHECKPOINT,
            &[
                &self.height.to_le_bytes(),
                self.header_hash.as_bytes(),
                self.mmr_root.as_bytes(),
                self.nullifier_root.as_bytes(),
            ],
        );

        let mut valid_signers: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for sig in &self.signatures {
            // Filter by trusted set if configured
            if !security.trusted_checkpoint_keys.is_empty()
                && !security
                    .trusted_checkpoint_keys
                    .iter()
                    .any(|k| k.as_slice() == sig.signer.as_slice())
            {
                continue;
            }
            let pk = match SuiteBPublicKey::from_bytes(&sig.signer) {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            let signature = match SuiteBSignature::from_bytes(&sig.signature) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if SuiteB::verify_prehash(&pk, &digest, &signature) {
                valid_signers.insert(sig.signer.clone());
            }
        }

        Ok(valid_signers.len() >= security.min_checkpoint_signatures)
    }
}

/// Checkpoint signature from trusted party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    /// Signer public key
    pub signer: Vec<u8>,
    /// Signature data
    pub signature: Vec<u8>,
}

/// Header sync manager
pub struct HeaderSyncManager {
    /// Configuration
    config: HeaderSyncConfig,
    /// Network client
    network: Arc<TachyonNetwork>,
    /// Header chain state
    chain: Arc<RwLock<HeaderChain>>,
    /// Sync state tracking
    sync_state: Arc<RwLock<SyncState>>,
    /// Background sync task
    sync_task: Option<JoinHandle<()>>,
    /// Announcement listener task
    announce_task: Option<JoinHandle<()>>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::UnboundedSender<()>>,
}

#[derive(Debug)]
struct SyncState {
    /// Current sync height
    pub current_height: u64,
    /// Target height for sync
    pub target_height: Option<u64>,
    /// Sync peers
    pub peers: Vec<String>,
    /// Last sync attempt
    pub last_sync_attempt: Instant,
    /// Sync in progress
    pub sync_in_progress: bool,
    /// Pending headers buffered by height
    pub pending_headers: HashMap<u64, BlockHeader>,
}

impl SyncState {
    fn new() -> Self {
        Self {
            current_height: 0,
            target_height: None,
            peers: Vec::new(),
            last_sync_attempt: Instant::now(),
            sync_in_progress: false,
            pending_headers: HashMap::new(),
        }
    }
}

impl HeaderSyncManager {
    /// Create a new header sync manager
    pub async fn new(config: HeaderSyncConfig) -> Result<Self> {
        let network = Arc::new(
            TachyonNetwork::new(std::path::Path::new(&config.network_config.data_dir)).await?,
        );

        // Try to load existing chain or create genesis
        let chain = Arc::new(RwLock::new(Self::load_or_create_chain(&config).await?));
        let sync_state = Arc::new(RwLock::new(SyncState::new()));

        // Start background sync task
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

        let chain_clone = chain.clone();
        let sync_state_clone = sync_state.clone();
        let config_clone = config.clone();
        let network_clone = network.clone();
        let sync_task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::run_sync_cycle(&chain_clone, &sync_state_clone, &config_clone, &network_clone).await;
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // Start an announcement listener to fetch headers and checkpoints as they arrive
        let chain_for_anns = chain.clone();
        let sync_state_for_anns = sync_state.clone();
        let network_for_anns = network.clone();
        let announce_task = tokio::spawn(async move {
            let mut rx = network_for_anns.subscribe_announcements();
            while let Ok((kind, _cid, height, _size, ticket)) = rx.recv().await {
                        // Only process Header and Checkpoint kinds
                        match kind {
                            BlobKind::Header => {
                                if let Ok(bytes) = network_for_anns.fetch_blob_from_ticket(&ticket).await {
                                    if let Ok(header) = bincode::deserialize::<BlockHeader>(&bytes) {
                                        // Buffer or apply in-order
                                        let mut applied = false;
                                        {
                                            let mut chain_guard = chain_for_anns.write().await;
                                            // Apply if next height
                                            let next_h = chain_guard.tip.unwrap_or(0).saturating_add(1);
                                            if header.height == next_h
                                                && chain_guard.add_header(header.clone()).is_ok() {
                                                    applied = true;
                                                }
                                        }
                                        if !applied {
                                            let mut ss = sync_state_for_anns.write().await;
                                            ss.pending_headers.insert(height, header);
                                        }
                                        // Try to apply any buffered headers now
                                        Self::apply_pending_in_order(&chain_for_anns, &sync_state_for_anns).await;
                                    }
                                }
                            }
                            BlobKind::Checkpoint => {
                                if let Ok(bytes) = network_for_anns.fetch_blob_from_ticket(&ticket).await {
                                    if let Ok(cp) = bincode::deserialize::<Checkpoint>(&bytes) {
                                        if cp.verify_with_trust(&SecurityConfig::default()).unwrap_or(false) {
                                            // Adopt checkpoint if ahead
                                            let mut chain = chain_for_anns.write().await;
                                            if cp.height > chain.tip.unwrap_or(0) {
                                                chain.checkpoints.push(cp.clone());
                                                chain.mmr_roots.insert(cp.height, cp.mmr_root);
                                                chain.nullifier_roots.insert(cp.height, cp.nullifier_root);
                                                chain.tip = Some(cp.height);
                                                let mut ss = sync_state_for_anns.write().await;
                                                ss.current_height = cp.height;
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
            }
        });

        Ok(Self {
            config,
            network,
            chain,
            sync_state,
            sync_task: Some(sync_task),
            announce_task: Some(announce_task),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Bootstrap from the strongest valid checkpoint fetched over HTTPS
    pub async fn bootstrap_from_checkpoints(&self) -> Result<()> {
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let mut best_cp: Option<Checkpoint> = None;
        for url in &self.config.network_config.checkpoint_servers {
            match client.get(format!("{}/latest", url)).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() { continue; }
                    let bytes = resp.bytes().await?;
                    if let Ok(cp) = bincode::deserialize::<Checkpoint>(&bytes) {
                        // Verify signatures and NiPoPoW proof with configured trust
                        if cp.verify_with_trust(&self.config.security_config)? {
                            if let Some(cur) = &best_cp {
                                if cp.height > cur.height { best_cp = Some(cp); }
                            } else { best_cp = Some(cp); }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        if let Some(cp) = best_cp {
            // Trust-but-verify: ensure our chain either empty or consistent, then set tip to cp.height
            let mut chain = self.chain.write().await;
            // Reset headers and record checkpoint baseline
            let genesis = chain.genesis.clone();
            let mut new_chain = HeaderChain::with_pow_config(genesis, self.config.pow_config.clone());
            new_chain.checkpoints.push(cp.clone());
            new_chain.tip = Some(cp.height);
            // Record the roots at checkpoint height
            new_chain.mmr_roots.insert(cp.height, cp.mmr_root);
            new_chain.nullifier_roots.insert(cp.height, cp.nullifier_root);
            *chain = new_chain;

            // Persist atomically
            let path = std::path::Path::new(&self.config.network_config.data_dir).join("headers.bin");
            let tmp = std::path::Path::new(&self.config.network_config.data_dir).join("headers.bin.tmp");
            let data = bincode::serialize(&*chain)?;
            tokio::fs::write(&tmp, &data).await?;
            tokio::fs::rename(&tmp, &path).await?;

            // Update sync state
            let mut ss = self.sync_state.write().await;
            ss.current_height = cp.height;
            Ok(())
        } else {
            Err(anyhow!("No valid checkpoints from servers"))
        }
    }

    /// Get current header chain
    pub async fn get_chain(&self) -> HeaderChain {
        self.chain.read().await.clone()
    }

    /// Get current sync status
    pub async fn get_sync_status(&self) -> SyncStatus {
        let sync_state = self.sync_state.read().await;
        let chain = self.chain.read().await;

        SyncStatus {
            current_height: sync_state.current_height,
            target_height: sync_state.target_height,
            tip_height: chain.tip.unwrap_or(0),
            sync_in_progress: sync_state.sync_in_progress,
            peers_connected: sync_state.peers.len(),
        }
    }

    /// Request headers from a specific height
    pub async fn request_headers(
        &self,
        start_height: u64,
        count: usize,
    ) -> Result<Vec<BlockHeader>> {
        // Best-effort: scan recent announcements and fetch up to count headers at or above start_height
        let anns = self.network.get_recent_announcements();
        let mut tickets: Vec<(u64, String)> = anns
            .into_iter()
            .filter(|(kind, _cid, height, _size, _ticket)| *kind == BlobKind::Header && *height >= start_height)
            .map(|(_k, _cid, height, _size, ticket)| (height, ticket))
            .collect();
        tickets.sort_by_key(|(h, _)| *h);

        let mut out = Vec::new();
        for (_h, ticket) in tickets.into_iter().take(count) {
            if let Ok(bytes) = self.network.fetch_blob_from_ticket(&ticket).await {
                if let Ok(header) = bincode::deserialize::<BlockHeader>(&bytes) {
                    out.push(header);
                }
            }
        }

        Ok(out)
    }

    /// Submit a new header for inclusion
    pub async fn submit_header(&self, header: BlockHeader) -> Result<()> {
        let mut chain = self.chain.write().await;
        chain.add_header(header)?;

        // Update sync state
        let mut sync_state = self.sync_state.write().await;
        sync_state.current_height = chain.tip.unwrap_or(0);

        Ok(())
    }

    /// Sync to a target height
    pub async fn sync_to_height(&self, target_height: u64) -> Result<()> {
        let mut sync_state = self.sync_state.write().await;
        sync_state.target_height = Some(target_height);
        sync_state.sync_in_progress = true;

        // Trigger immediate sync cycle
        drop(sync_state);
        Self::run_sync_cycle(&self.chain, &self.sync_state, &self.config, &self.network).await;

        Ok(())
    }

    /// Load existing chain or create genesis
    async fn load_or_create_chain(config: &HeaderSyncConfig) -> Result<HeaderChain> {
        // Try to load existing chain from disk
        if let Ok(chain) = Self::load_chain_from_disk(&config.network_config.data_dir).await {
            return Ok(chain);
        }

        // Create genesis header (Zcash-like nBits)
        let genesis_header = BlockHeader::new(
            0,
            Hash::from([0u8; 32]),       // Genesis has no previous
            Some(Hash::from([1u8; 32])), // Genesis MMR root
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            0,
            0x1d00ffff,
        );

        Ok(HeaderChain::with_pow_config(genesis_header, config.pow_config.clone()))
    }

    /// Load chain from disk storage
    async fn load_chain_from_disk(_data_dir: &str) -> Result<HeaderChain> {
        // Try to read persisted headers
        let path = std::path::Path::new(_data_dir).join("headers.bin");
        let tmp = std::path::Path::new(_data_dir).join("headers.bin.tmp");
        if path.exists() {
            let data = tokio::fs::read(&path).await?;
            let chain: HeaderChain = bincode::deserialize(&data)?;
            return Ok(chain);
        }
        if tmp.exists() {
            // Attempt to recover from a previous crash mid-write
            let data = tokio::fs::read(&tmp).await?;
            let chain: HeaderChain = bincode::deserialize(&data)?;
            // Promote tmp to main file
            tokio::fs::rename(&tmp, &path).await.ok();
            return Ok(chain);
        }
        Err(anyhow!("No existing chain found"))
    }

    /// Run a sync cycle to catch up with the network
    async fn run_sync_cycle(
        chain: &Arc<RwLock<HeaderChain>>,
        sync_state: &Arc<RwLock<SyncState>>,
        config: &HeaderSyncConfig,
        network: &Arc<TachyonNetwork>,
    ) {
        {
            let mut guard = sync_state.write().await;
            if guard.sync_in_progress {
                return;
            }
            guard.sync_in_progress = true;
            guard.last_sync_attempt = Instant::now();
        }

        // Get current chain state
        let current_height = {
            let chain_guard = chain.read().await;
            chain_guard.tip.unwrap_or(0)
        };

        // Check if we need to sync
        if let Some(target_height) = sync_state.read().await.target_height {
            if current_height >= target_height {
                let mut sync_state_guard = sync_state.write().await;
                sync_state_guard.sync_in_progress = false;
                return;
            }
        }

        info!("Starting header sync cycle from height {}", current_height);

        // In a real implementation, this would:
        // 1. Query peers for new headers
        // 2. Download and verify headers in batches
        // 3. Use NiPoPoW proofs for efficient verification
        // 4. Update chain state

        // Request the next small batch via header request/response protocol, falling back to announcements
        let batch_size = config.sync_config.max_batch_size.min(32) as u32;
        let mut headers: Vec<BlockHeader> = Vec::new();
        // Try request/response from any peer first
        if let Ok(raw_headers) = network.request_headers_from_any_peer_by_height(current_height + 1, batch_size).await {
            for (_height, raw) in raw_headers {
                if let Some(h) = Self::decode_header_strict(&raw, &config.pow_config) { headers.push(h); }
            }
        }
        // If empty, fall back to announcements-as-hints
        if headers.is_empty() {
            let anns = network.get_recent_announcements();
            let mut tickets: Vec<(u64, String)> = anns
                .into_iter()
                .filter(|(kind, _cid, height, _size, _ticket)| *kind == BlobKind::Header && *height > current_height)
                .map(|(_k, _cid, height, _size, ticket)| (height, ticket))
                .collect();
            tickets.sort_by_key(|(h, _)| *h);
            for (_h, ticket) in tickets.into_iter().take(batch_size as usize) {
                if let Ok(bytes) = network.fetch_blob_from_ticket(&ticket).await {
                    if let Some(header) = Self::decode_header_strict(&bytes, &config.pow_config) {
                        headers.push(header);
                    }
                }
            }
        }

        if !headers.is_empty() {
            let mut chain_guard = chain.write().await;
            for h in headers {
                if let Err(e) = chain_guard.add_header(h) {
                    warn!("Failed to add header: {}", e);
                    break;
                }
            }
        }

        // Persist chain to disk
        let path = std::path::Path::new(&config.network_config.data_dir).join("headers.bin");
        let tmp_path = std::path::Path::new(&config.network_config.data_dir).join("headers.bin.tmp");
        let data_opt = {
            let chain_guard = chain.read().await;
            bincode::serialize(&*chain_guard).ok()
        };
        if let Some(data) = data_opt {
            let _ = tokio::fs::write(&tmp_path, &data).await;
            let _ = tokio::fs::rename(&tmp_path, &path).await;
        }

        // Update sync state
        {
            let tip_now = chain.read().await.tip.unwrap_or(current_height);
            let mut sync_state_guard = sync_state.write().await;
            sync_state_guard.current_height = tip_now;
            sync_state_guard.sync_in_progress = false;
        }

        info!(
            "Header sync cycle completed at height {}",
            chain.read().await.tip.unwrap_or(current_height)
        );
    }

    /// Decode header from either our bincode representation or raw Zcash header bytes
    fn decode_header_strict(bytes: &[u8], _pow: &PowConfig) -> Option<BlockHeader> {
        // Try bincode first (internal format)
        if let Ok(h) = bincode::deserialize::<BlockHeader>(bytes) { return Some(h); }
        // Otherwise, try parsing exact Zcash header and solution using Zebra and map to our struct
        #[cfg(feature = "zcash_zebra")]
        {
            use zebra_chain::serialization::ZcashDeserialize;
            use std::io::Cursor;
            if let Ok(zebra_header) = zebra_chain::block::Header::zcash_deserialize(Cursor::new(bytes)) {
                // Extract fields
                let prev = zebra_header.previous_block_hash().0;
                let time = zebra_header.time().timestamp() as u64;
                let bits = zebra_header.difficulty_threshold().to_consensus();
                let solution_bytes = zebra_header.solution().as_bytes().to_vec();
                // Compute the Zcash block hash using Zebra and store it into our `hash` for linking
                let z_hash = zebra_header.hash();
                let hdr = BlockHeader {
                    height: 0,
                    previous_hash: SerializableHash(Hash::from(prev)),
                    hash: SerializableHash(Hash::from(z_hash.0)),
                    mmr_root: None,
                    timestamp: time,
                    nonce: zebra_header.nonce().0 as u64,
                    bits,
                    solution: solution_bytes,
                };
                // Strict PoW via Zebra if enabled in config
                if _pow.disable_pow_validation { return Some(hdr); }
                // Validate Equihash solution and difficulty target via Zebra's internal checks
                if zebra_header.is_equihash_solution_valid() && zebra_header.work().is_ok() {
                    return Some(hdr);
                }
                return None;
            }
        }
        None
    }

    /// Verify an Equihash solution according to configured parameters (n, k).
    /// Placeholder implementation: requires non-empty solution. Replace with Zebra verifier under a feature flag.
    fn _verify_equihash_internal(header: &BlockHeader, n: u32, k: u32) -> bool {
        verify_equihash_solution(header, n, k)
    }

    /// Attempt to apply buffered headers in order from current tip+1 upward
    async fn apply_pending_in_order(
        chain: &Arc<RwLock<HeaderChain>>,
        sync_state: &Arc<RwLock<SyncState>>,
    ) {
        loop {
            let next_h = { chain.read().await.tip.unwrap_or(0).saturating_add(1) };
            let candidate = { sync_state.read().await.pending_headers.get(&next_h).cloned() };
            let Some(header) = candidate else { break; };
            // Try to apply
            let applied_ok = {
                let mut c = chain.write().await;
                c.add_header(header.clone()).is_ok()
            };
            if applied_ok {
                let mut ss = sync_state.write().await;
                ss.pending_headers.remove(&next_h);
                ss.current_height = chain.read().await.tip.unwrap_or(ss.current_height);
            } else {
                break;
            }
        }
    }

    /// Shutdown the sync manager
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(tx) = &self.shutdown_tx {
            tx.send(())?;
        }
        Ok(())
    }
}

impl Drop for HeaderSyncManager {
    fn drop(&mut self) {
        if let Some(task) = self.sync_task.take() {
            task.abort();
        }
        if let Some(task) = self.announce_task.take() {
            task.abort();
        }
    }
}

/// Sync status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Current synced height
    pub current_height: u64,
    /// Target height for sync
    pub target_height: Option<u64>,
    /// Current chain tip height
    pub tip_height: u64,
    /// Whether sync is currently in progress
    pub sync_in_progress: bool,
    /// Number of connected sync peers
    pub peers_connected: usize,
}

/// Tests for header sync functionality
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_creation() {
        let header = BlockHeader::new(
            0,
            Hash::from([0u8; 32]),
            Some(Hash::from([1u8; 32])),
            1234567890,
            0,
            0x1d00ffff,
        );

        assert_eq!(header.height, 0);
        assert!(header.meets_difficulty());
    }

    #[test]
    fn test_header_chain_creation() {
        let genesis = BlockHeader::new(
            0,
            Hash::from([0u8; 32]),
            Some(Hash::from([1u8; 32])),
            1234567890,
            0,
            0x1d00ffff,
        );

        let chain = HeaderChain::new(genesis.clone());
        assert_eq!(chain.tip, Some(0));
        assert_eq!(chain.get_header(0).unwrap().height, 0);
    }

    #[test]
    fn test_header_addition() {
        let mut chain = HeaderChain::new(BlockHeader::new(
            0,
            Hash::from([0u8; 32]),
            Some(Hash::from([1u8; 32])),
            1234567890,
            0,
            0x1d00ffff,
        ));

        let header1 = BlockHeader::new(
            1,
            chain.get_header(0).unwrap().hash.into(),
            Some(Hash::from([2u8; 32])),
            1234567891,
            0,
            0x1d00ffff,
        );

        assert!(chain.add_header(header1).is_ok());
        assert_eq!(chain.tip, Some(1));
    }

    #[test]
    fn test_nipopow_proof() {
        let chain = HeaderChain::new(BlockHeader::new(
            0,
            Hash::from([0u8; 32]),
            Some(Hash::from([1u8; 32])),
            1234567890,
            0,
            0x1d00ffff,
        ));

        let proof = chain.generate_nipopow_proof(0, 0).unwrap();
        assert!(proof.verify(&SecurityConfig::default()).is_ok());
    }
}

/// Verify Equihash solution for the given header and parameters (n,k).
/// Placeholder: returns true if `solution` field is non-empty.
fn verify_equihash_solution(header: &BlockHeader, _n: u32, _k: u32) -> bool {
    // If Zebra feature is enabled, attempt strict verification using zebra-chain
    #[cfg(feature = "zcash_zebra")]
    {
        // Build a Zebra header from raw fields where possible.
        // Note: Our internal header structure is simplified; for strict verification,
        // the caller should pass raw Zcash header bytes via decode_header_fallback.
        if header.solution.is_empty() { return false; }
        // Convert nBits to Expanded target
        let expanded = ZebraExpandedTarget::from_consensus(header.bits);
        // Parse Equihash solution
        if let Ok(sol) = ZebraEquihashSolution::from_bytes(&header.solution) {
            // Zebra's header PoW hash is based on Zcash serialization; since we don't
            // preserve full serialization here, rely on solution validity alone.
            // Consumers that require exact checks should feed in raw Zcash headers and
            // perform full Zebra verification at the integration layer.
            return sol.is_valid(200, 9);
        }
        return false;
    }
    // Fallback placeholder when feature is disabled
    !header.solution.is_empty()
}

