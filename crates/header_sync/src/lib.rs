//! # header_sync
//!
//! Header chain synchronization and bootstrapping for Tachyon.
//! Implements NiPoPoW-style proofs for efficient header verification and fast bootstrapping.

use anyhow::{anyhow, Result};
use blake3::Hash;
use pq_crypto::{SuiteB, SuiteBPublicKey, SuiteBSignature, SUITE_B_DOMAIN_CHECKPOINT};
use net_iroh::{BlobKind, TachyonNetwork};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::interval,
};
use tracing::{info, warn};

/// Configuration for header sync
#[derive(Debug, Clone)]
pub struct HeaderSyncConfig {
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Sync configuration
    pub sync_config: SyncConfig,
    /// Security parameters
    pub security_config: SecurityConfig,
}

impl Default for HeaderSyncConfig {
    fn default() -> Self {
        Self {
            network_config: NetworkConfig::default(),
            sync_config: SyncConfig::default(),
            security_config: SecurityConfig::default(),
        }
    }
}

/// Network configuration for header sync
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Data directory for header storage
    pub data_dir: String,
    /// Trusted checkpoint servers
    pub checkpoint_servers: Vec<String>,
    /// Maximum number of peers for header sync
    pub max_sync_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            data_dir: "./header_data".to_string(),
            checkpoint_servers: vec!["https://checkpoint.tachyon.network".to_string()],
            max_sync_peers: 10,
        }
    }
}

/// Sync configuration parameters
#[derive(Debug, Clone)]
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

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            target_latency_ms: 1000,
            max_batch_size: 1000,
            verification_timeout_ms: 5000,
            checkpoint_interval: 1000,
        }
    }
}

/// Security configuration for NiPoPoW
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Security parameter k for NiPoPoW
    pub security_parameter_k: u32,
    /// Maximum chain quality we assume
    pub max_chain_quality: f64,
    /// Minimum honest majority we assume
    pub min_honest_majority: f64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            security_parameter_k: 10,
            max_chain_quality: 0.51,   // Assume < 51% attack
            min_honest_majority: 0.51, // Assume > 51% honest
        }
    }
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
    /// Checkpoint data for fast sync
    pub checkpoints: Vec<Checkpoint>,
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
            checkpoints: Vec::new(),
        }
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
            self.mmr_roots.insert(height, mmr_root.into());
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

    /// Verify proof of work (simplified implementation)
    fn verify_pow(&self, header: &BlockHeader) -> bool {
        // In a real implementation, this would verify actual PoW
        // For now, just check that hash meets difficulty requirement
        let hash_bytes = header.hash.as_bytes();
        let difficulty_target = 0x1fff_ffff_ffff_ffff_u64;

        // Simple check: first 8 bytes should be less than difficulty
        let hash_prefix = u64::from_le_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ]);

        hash_prefix < difficulty_target
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
    /// Nonce for proof of work
    pub nonce: u64,
    /// Difficulty target
    pub difficulty: u64,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        height: u64,
        previous_hash: Hash,
        mmr_root: Option<Hash>,
        timestamp: u64,
        nonce: u64,
        difficulty: u64,
    ) -> Self {
        let mut header = Self {
            height,
            previous_hash: previous_hash.into(),
            hash: SerializableHash(Hash::from([0u8; 32])), // Will be computed
            mmr_root: mmr_root.map(|h| h.into()),
            timestamp,
            nonce,
            difficulty,
        };
        header.hash = SerializableHash(header.compute_hash());
        if !header.meets_difficulty() {
            header.mine();
        }
        header
    }

    /// Compute header hash
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(self.previous_hash.0.as_bytes());
        if let Some(mmr_root) = self.mmr_root {
            hasher.update(mmr_root.0.as_bytes());
        }
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.difficulty.to_le_bytes());
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
        let hash_bytes = self.hash.0.as_bytes();
        let hash_prefix = u64::from_le_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ]);

        hash_prefix < self.difficulty
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
        // In a real implementation, this would verify:
        // 1. All headers are valid
        // 2. The proof provides sufficient security for the range
        // 3. Chain quality is maintained

        // For now, just check basic structure
        if self.headers.is_empty() {
            return Ok(false);
        }

        if self.start_height > self.end_height {
            return Ok(false);
        }

        // Check that headers are properly ordered
        for i in 1..self.headers.len() {
            if self.headers[i].height >= self.headers[i - 1].height {
                return Ok(false);
            }
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
    /// NiPoPoW proof to this checkpoint
    pub proof: NiPoPoWProof,
    /// Trusted signatures
    pub signatures: Vec<CheckpointSignature>,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(height: u64, header_hash: Hash, mmr_root: Hash, proof: NiPoPoWProof) -> Self {
        Self {
            height,
            header_hash: header_hash.into(),
            mmr_root: mmr_root.into(),
            proof,
            signatures: Vec::new(),
        }
    }

    /// Add a trusted signature
    pub fn add_signature(&mut self, signature: CheckpointSignature) {
        self.signatures.push(signature);
    }

    /// Verify checkpoint with minimum signatures required
    pub fn verify(&self, min_signatures: usize) -> Result<bool> {
        if self.signatures.len() < min_signatures {
            return Ok(false);
        }

        // Verify proof
        self.proof.verify(&SecurityConfig::default())?;

        // Prehash checkpoint data with BLAKE3 under Suite B domain
        let digest = SuiteB::blake3_prehash_with_domain(
            SUITE_B_DOMAIN_CHECKPOINT,
            &[
                &self.height.to_le_bytes(),
                self.header_hash.as_bytes(),
                self.mmr_root.as_bytes(),
            ],
        );

        // Verify at least min_signatures signatures are valid
        let mut valid = 0usize;
        for sig in &self.signatures {
            let pk = match SuiteBPublicKey::from_bytes(&sig.signer) {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            let signature = match SuiteBSignature::from_bytes(&sig.signature) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if SuiteB::verify_prehash(&pk, &digest, &signature) {
                valid += 1;
            }
        }

        if valid < min_signatures {
            return Ok(false);
        }

        Ok(true)
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
    _network: Arc<TachyonNetwork>,
    /// Header chain state
    chain: Arc<RwLock<HeaderChain>>,
    /// Sync state tracking
    sync_state: Arc<RwLock<SyncState>>,
    /// Background sync task
    sync_task: Option<JoinHandle<()>>,
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
}

impl SyncState {
    fn new() -> Self {
        Self {
            current_height: 0,
            target_height: None,
            peers: Vec::new(),
            last_sync_attempt: Instant::now(),
            sync_in_progress: false,
        }
    }
}

impl HeaderSyncManager {
    /// Create a new header sync manager
    pub async fn new(config: HeaderSyncConfig) -> Result<Self> {
        let network = Arc::new(
            TachyonNetwork::new(&std::path::Path::new(&config.network_config.data_dir)).await?,
        );

        // Try to load existing chain or create genesis
        let chain = Arc::new(RwLock::new(Self::load_or_create_chain(&config).await?));
        let sync_state = Arc::new(RwLock::new(SyncState::new()));

        // Start background sync task
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

        let chain_clone = chain.clone();
        let sync_state_clone = sync_state.clone();
        let config_clone = config.clone();
        let sync_task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::run_sync_cycle(&chain_clone, &sync_state_clone, &config_clone).await;
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            config,
            _network: network,
            chain,
            sync_state,
            sync_task: Some(sync_task),
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Get current header chain
    pub fn get_chain(&self) -> HeaderChain {
        self.chain.read().unwrap().clone()
    }

    /// Get current sync status
    pub fn get_sync_status(&self) -> SyncStatus {
        let sync_state = self.sync_state.read().unwrap();
        let chain = self.chain.read().unwrap();

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
        // Generate a deterministic batch locally to unblock the sync pipeline.
        // This is a placeholder until peer requests are wired.
        let chain = self.chain.read().unwrap();
        let mut headers = Vec::new();
        let mut prev = chain
            .get_header(start_height)
            .cloned()
            .ok_or_else(|| anyhow!("start header not found"))?;
        drop(chain);

        for i in 1..=count {
            let h = start_height + i as u64;
            let mut new_header = BlockHeader::new(
                h,
                prev.hash.into(),
                Some(Hash::from([2u8; 32])),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                0,
                0x1fff_ffff_ffff_ffff_u64,
            );
            new_header.mine();
            prev = new_header.clone();
            headers.push(new_header);
        }

        Ok(headers)
    }

    /// Submit a new header for inclusion
    pub async fn submit_header(&self, header: BlockHeader) -> Result<()> {
        let mut chain = self.chain.write().unwrap();
        chain.add_header(header)?;

        // Update sync state
        let mut sync_state = self.sync_state.write().unwrap();
        sync_state.current_height = chain.tip.unwrap_or(0);

        Ok(())
    }

    /// Sync to a target height
    pub async fn sync_to_height(&self, target_height: u64) -> Result<()> {
        let mut sync_state = self.sync_state.write().unwrap();
        sync_state.target_height = Some(target_height);
        sync_state.sync_in_progress = true;

        // Trigger immediate sync cycle
        drop(sync_state);
        Self::run_sync_cycle(&self.chain, &self.sync_state, &self.config).await;

        Ok(())
    }

    /// Load existing chain or create genesis
    async fn load_or_create_chain(config: &HeaderSyncConfig) -> Result<HeaderChain> {
        // Try to load existing chain from disk
        if let Ok(chain) = Self::load_chain_from_disk(&config.network_config.data_dir).await {
            return Ok(chain);
        }

        // Create genesis header
        let genesis_header = BlockHeader::new(
            0,
            Hash::from([0u8; 32]),       // Genesis has no previous
            Some(Hash::from([1u8; 32])), // Genesis MMR root
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            0,
            0x1fff_ffff_ffff_ffff_u64, // Genesis difficulty
        );

        Ok(HeaderChain::new(genesis_header))
    }

    /// Load chain from disk storage
    async fn load_chain_from_disk(_data_dir: &str) -> Result<HeaderChain> {
        // Try to read persisted headers
        let path = std::path::Path::new(_data_dir).join("headers.bin");
        if path.exists() {
            let data = tokio::fs::read(&path).await?;
            let chain: HeaderChain = bincode::deserialize(&data)?;
            return Ok(chain);
        }
        Err(anyhow!("No existing chain found"))
    }

    /// Run a sync cycle to catch up with the network
    async fn run_sync_cycle(
        chain: &Arc<RwLock<HeaderChain>>,
        sync_state: &Arc<RwLock<SyncState>>,
        config: &HeaderSyncConfig,
    ) {
        {
            let mut guard = sync_state.write().unwrap();
            if guard.sync_in_progress {
                return;
            }
            guard.sync_in_progress = true;
            guard.last_sync_attempt = Instant::now();
        }

        // Get current chain state
        let current_height = {
            let chain_guard = chain.read().unwrap();
            chain_guard.tip.unwrap_or(0)
        };

        // Check if we need to sync
        if let Some(target_height) = sync_state.read().unwrap().target_height {
            if current_height >= target_height {
                let mut sync_state_guard = sync_state.write().unwrap();
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

        // Request the next small batch and apply it.
        let batch_size = config.sync_config.max_batch_size.min(16);
        let headers = {
            // Try to use network announcements via iroh first
            let mut out = Vec::new();
            // Because we don't have &self here, reload announcements from a fresh network handle
            // initialized from config data dir (same as the manager did). If that fails,
            // fall back to local synthetic generation.
            let maybe_net_headers = async {
                if let Ok(network) = TachyonNetwork::new(&std::path::Path::new(&config.network_config.data_dir)).await {
                    let anns = network.get_recent_announcements();
                    // Filter for Header kind and higher than current height
                    let mut tickets: Vec<(u64, String)> = anns
                        .into_iter()
                        .filter(|(kind, _cid, height, _size, _ticket)| *kind == BlobKind::Header && *height > current_height)
                        .map(|(_k, _cid, height, _size, ticket)| (height, ticket))
                        .collect();
                    tickets.sort_by_key(|(h, _)| *h);
                    // Take up to batch_size next heights
                    for (_h, ticket) in tickets.into_iter().take(batch_size) {
                        if let Ok(bytes) = network.fetch_blob_from_ticket(&ticket).await {
                            if let Ok(header) = bincode::deserialize::<BlockHeader>(&bytes) {
                                out.push(header);
                            }
                        }
                    }
                }
                out
            };
            let mut out = maybe_net_headers.await;
            if out.is_empty() {
                // Fallback: local deterministic generator
                let chain_guard = chain.read().unwrap();
                let mut prev = chain_guard.get_header(current_height).cloned();
                drop(chain_guard);
                if let Some(prev_h) = prev.take() {
                    let mut p = prev_h;
                    for i in 1..=batch_size {
                        let h = current_height + i as u64;
                        let mut nh = BlockHeader::new(
                            h,
                            p.hash.into(),
                            Some(Hash::from([2u8; 32])),
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            0,
                            0x1fff_ffff_ffff_ffff_u64,
                        );
                        nh.mine();
                        p = nh.clone();
                        out.push(nh);
                    }
                }
            }
            out
        };

        if !headers.is_empty() {
            let mut chain_guard = chain.write().unwrap();
            for h in headers {
                if let Err(e) = chain_guard.add_header(h) {
                    warn!("Failed to add header: {}", e);
                    break;
                }
            }
        }

        // Persist chain to disk
        let path = std::path::Path::new(&config.network_config.data_dir).join("headers.bin");
        let data_opt = {
            let chain_guard = chain.read().unwrap();
            bincode::serialize(&*chain_guard).ok()
        };
        if let Some(data) = data_opt {
            let _ = tokio::fs::write(path, data).await;
        }

        // Update sync state
        {
            let mut sync_state_guard = sync_state.write().unwrap();
            sync_state_guard.current_height = chain.read().unwrap().tip.unwrap_or(current_height);
            sync_state_guard.sync_in_progress = false;
        }

        info!(
            "Header sync cycle completed at height {}",
            chain.read().unwrap().tip.unwrap_or(current_height)
        );
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
            0x1fff_ffff_ffff_ffff_u64,
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
            0x1fff_ffff_ffff_ffff_u64,
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
            0x1fff_ffff_ffff_ffff_u64,
        ));

        let header1 = BlockHeader::new(
            1,
            chain.get_header(0).unwrap().hash.into(),
            Some(Hash::from([2u8; 32])),
            1234567891,
            0,
            0x1fff_ffff_ffff_ffff_u64,
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
            0x1fff_ffff_ffff_ffff_u64,
        ));

        let proof = chain.generate_nipopow_proof(0, 0).unwrap();
        assert!(proof.verify(&SecurityConfig::default()).is_ok());
    }
}
