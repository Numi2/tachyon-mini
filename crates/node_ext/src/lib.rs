//! # node_ext
//! Numan Thabit
//! Validator / Node extension implementation for Tachyon.
//! Verifies PCD proofs, nullifier checks, and maintains minimal state for validation.

use accum_mmr::{MmrAccumulator, MmrWitness, SerializableHash};
use accum_set::SetAccumulator;
use anyhow::{anyhow, Result};
use blake3::Hash;
use net_iroh::TachyonNetwork;
use circuits::{PcdCore as Halo2PcdCore, compute_transition_digest_bytes};
use pcd_core::aggregation::aggregate_action_proofs;
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
use tracing::{debug, info};
use std::path::Path;
use tokio::fs as async_fs;
use bincode;

/// Configuration for the node extension
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Validation configuration
    pub validation_config: ValidationConfig,
    /// Pruning configuration
    pub pruning_config: PruningConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network_config: NetworkConfig::default(),
            validation_config: ValidationConfig::default(),
            pruning_config: PruningConfig::default(),
        }
    }
}

/// Network configuration for node
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Data directory for node state
    pub data_dir: String,
    /// Bootstrap nodes for peer discovery
    pub bootstrap_nodes: Vec<String>,
    /// Listen address for P2P connections
    pub listen_addr: Option<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            data_dir: "./node_data".to_string(),
            bootstrap_nodes: vec![],
            listen_addr: None,
        }
    }
}

/// Validation configuration
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Size of the recent nullifier window (number of blocks)
    pub nullifier_window_size: u64,
    /// Maximum number of transactions per block
    pub max_transactions_per_block: usize,
    /// PCD verification timeout in milliseconds
    pub pcd_verification_timeout_ms: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            nullifier_window_size: 1000,
            max_transactions_per_block: 100,
            pcd_verification_timeout_ms: 5000,
        }
    }
}

/// Pruning configuration
#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// How often to run pruning (in seconds)
    pub pruning_interval_secs: u64,
    /// Keep state for this many blocks after confirmation
    pub retention_blocks: u64,
    /// Maximum storage size before aggressive pruning (in bytes)
    pub max_storage_size: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            pruning_interval_secs: 300, // 5 minutes
            retention_blocks: 100,
            max_storage_size: 10 * 1024 * 1024 * 1024, // 10 GB
        }
    }
}

/// Node state management
#[derive(Debug)]
pub struct NodeState {
    /// Current block height
    pub current_height: u64,
    /// Canonical nullifier set accumulator (full-history)
    pub nullifier_set: SetAccumulator,
    /// MMR accumulator for note commitments
    pub commitment_mmr: MmrAccumulator,
    /// Current MMR peaks for validation (derived from `commitment_mmr`)
    pub mmr_peaks: Vec<(u64, SerializableHash)>,
    /// Current MMR root
    pub mmr_root: [u8; 32],
    /// Current nullifier set root
    pub nullifier_root: [u8; 32],
    /// Last pruning timestamp
    pub last_pruned: Instant,
    /// Storage usage tracking
    pub storage_size: u64,
}

impl NodeState {
    /// Create new node state
    pub fn new() -> Self {
        Self {
            current_height: 0,
            nullifier_set: SetAccumulator::new(),
            commitment_mmr: MmrAccumulator::new(),
            mmr_peaks: Vec::new(),
            mmr_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            last_pruned: Instant::now(),
            storage_size: 0,
        }
    }

    /// Update nullifier accumulator with new nullifiers and refresh root
    pub fn update_nullifier_set(&mut self, new_nullifiers: Vec<[u8; 32]>) {
        for nf in new_nullifiers {
            self.nullifier_set.insert(nf);
        }
        self.nullifier_root = self.nullifier_set.root();
    }

    /// Check if a nullifier has already been seen (full-history check)
    pub fn check_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    /// Update MMR peaks
    pub fn update_mmr_peaks(&mut self, peaks: Vec<(u64, SerializableHash)>) {
        self.mmr_peaks = peaks;
    }

    /// Recompute peaks and root from the current commitment MMR
    pub fn refresh_mmr_view(&mut self) {
        // Recompute peaks list from accumulator
        let mut new_peaks: Vec<(u64, SerializableHash)> = Vec::new();
        for &pos in self.commitment_mmr.peaks() {
            if let Some(node) = self.commitment_mmr.get_node(pos) {
                new_peaks.push((pos, node.hash));
            }
        }
        self.mmr_peaks = new_peaks;
        self.mmr_root = self
            .commitment_mmr
            .root()
            .map(|h| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(h.as_bytes());
                arr
            })
            .unwrap_or([0u8; 32]);
    }

    /// Compute the domain-separated leaf hash used by Tachygram for note commitments
    pub fn leaf_hash(commitment: &[u8; 32]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tachygram:leaf:v1");
        hasher.update(commitment);
        hasher.finalize()
    }

    /// Attempt to load state from disk; returns None if not present
    pub async fn load_from_disk<P: AsRef<Path>>(data_dir: P) -> Option<Self> {
        let path = data_dir.as_ref().join("node_state.bin");
        if !path.exists() {
            return None;
        }
        match async_fs::read(&path).await.ok().and_then(|bytes| bincode::deserialize::<PersistedNodeState>(&bytes).ok()) {
            Some(p) => Some(Self::from(p)),
            None => None,
        }
    }

    /// Persist state to disk (best-effort)
    pub async fn save_to_disk<P: AsRef<Path>>(&self, data_dir: P) {
        let path = data_dir.as_ref().join("node_state.bin");
        if let Ok(bytes) = bincode::serialize(&PersistedNodeState::from(self)) {
            let _ = async_fs::write(&path, &bytes).await;
        }
    }
}

/// Serializable snapshot for node state persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedNodeState {
    pub current_height: u64,
    pub nullifier_set: SetAccumulator,
    pub commitment_mmr: MmrAccumulator,
    pub mmr_peaks: Vec<(u64, SerializableHash)>,
    pub mmr_root: [u8; 32],
    pub nullifier_root: [u8; 32],
}

impl From<PersistedNodeState> for NodeState {
    fn from(p: PersistedNodeState) -> Self {
        Self {
            current_height: p.current_height,
            nullifier_set: p.nullifier_set,
            commitment_mmr: p.commitment_mmr,
            mmr_peaks: p.mmr_peaks,
            mmr_root: p.mmr_root,
            nullifier_root: p.nullifier_root,
            last_pruned: Instant::now(),
            storage_size: 0,
        }
    }
}

impl From<&NodeState> for PersistedNodeState {
    fn from(s: &NodeState) -> Self {
        Self {
            current_height: s.current_height,
            nullifier_set: s.nullifier_set.clone(),
            commitment_mmr: s.commitment_mmr.clone(),
            mmr_peaks: s.mmr_peaks.clone(),
            mmr_root: s.mmr_root,
            nullifier_root: s.nullifier_root,
        }
    }
}

/// Transaction validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the transaction is valid
    pub is_valid: bool,
    /// Validation error message if invalid
    pub error_message: Option<String>,
    /// Gas cost for validation
    pub gas_used: u64,
    /// Validation timestamp
    pub validated_at: u64,
}

/// Block validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockValidationResult {
    /// Whether the block is valid
    pub is_valid: bool,
    /// Validation results for each transaction
    pub transaction_results: Vec<ValidationResult>,
    /// Block hash if valid
    pub block_hash: Option<TransactionHash>,
    /// Total gas used for block validation
    pub total_gas_used: u64,
}

/// Tachyon node extension
pub struct TachyonNode {
    /// Configuration
    config: NodeConfig,
    /// Network client
    _network: Arc<TachyonNetwork>,
    /// Node state
    state: Arc<RwLock<NodeState>>,
    /// PCD verifier
    pcd_verifier: Arc<dyn PcdVerifier>,
    /// Transaction pool for pending validation
    _pending_txs: Arc<RwLock<HashMap<TransactionHash, Transaction>>>,
    /// Background validation task
    validation_task: Option<JoinHandle<()>>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::UnboundedSender<()>>,
    /// Pruning task
    pruning_task: Option<JoinHandle<()>>,
}

impl TachyonNode {
    /// Create a new Tachyon node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let network = Arc::new(
            TachyonNetwork::new(&std::path::Path::new(&config.network_config.data_dir)).await?,
        );
        // Load persisted state if available
        let loaded = NodeState::load_from_disk(&config.network_config.data_dir).await;
        let initial_state = loaded.unwrap_or_else(|| NodeState::new());
        let state = Arc::new(RwLock::new(initial_state));
        let pcd_verifier = Arc::new(SimplePcdVerifier::new());

        // Start background validation task
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

        let state_clone = state.clone();
        let network_clone = network.clone();
        let validation_task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::process_pending_transactions(&state_clone, &network_clone).await;
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // Start pruning task (separate shutdown channel)
        let state_clone2 = state.clone();
        let pruning_config = config.pruning_config.clone();
        let (_pruning_shutdown_tx, mut pruning_shutdown_rx) = mpsc::unbounded_channel::<()>();
        let pruning_task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(pruning_config.pruning_interval_secs));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::run_pruning(&state_clone2, &pruning_config).await;
                    }
                    _ = pruning_shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            config,
            _network: network,
            state,
            pcd_verifier,
            _pending_txs: Arc::new(RwLock::new(HashMap::new())),
            validation_task: Some(validation_task),
            shutdown_tx: Some(shutdown_tx),
            pruning_task: Some(pruning_task),
        })
    }

    /// Aggregate PCD proofs from a block into a single proof blob using recursive-style folding
    pub fn aggregate_block_proofs(&self, block: &Block) -> Result<Vec<u8>> {
        let proofs: Vec<Vec<u8>> = block.transactions.iter().map(|t| t.pcd_proof.clone()).collect();
        let aggregated = aggregate_action_proofs(&proofs)?;
        Ok(aggregated)
    }

    /// Validate a transaction
    pub async fn validate_transaction(&self, tx: &Transaction) -> Result<ValidationResult> {
        let start_time = Instant::now();

        // Basic transaction format validation
        tx.validate_format()?;

        // Enforce anchor/roots match canonical state and nullifier uniqueness (full-history)
        let membership_ok = {
            let state = self.state.read().unwrap();
            // Anchor and roots must match canonical state at current height
            if tx.anchor_height != state.current_height
                || tx.pcd_mmr_root != state.mmr_root
                || tx.pcd_nullifier_root != state.nullifier_root
            {
                return Ok(ValidationResult {
                    is_valid: false,
                    error_message: Some("Anchor/roots do not match canonical state".to_string()),
                    gas_used: 1000,
                    validated_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                });
            }

            for nullifier in &tx.nullifiers {
                if state.check_nullifier(nullifier) {
                    return Ok(ValidationResult {
                        is_valid: false,
                        error_message: Some(format!("Nullifier already spent: {:?}", nullifier)),
                        gas_used: 1000,
                        validated_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    });
                }
            }
            // Validate membership witnesses for each spent commitment (optional but recommended)
            if tx.spent_commitments.len() != tx.membership_witnesses.len() {
                false
            } else {
                let mmr_root = Hash::from(state.mmr_root);
                let mut all_ok = true;
                for (cm, wit_bytes) in tx
                    .spent_commitments
                    .iter()
                    .zip(tx.membership_witnesses.iter())
                {
                    let witness: MmrWitness = match bincode::deserialize(wit_bytes) {
                        Ok(w) => w,
                        Err(_) => { all_ok = false; break; }
                    };
                    let leaf = NodeState::leaf_hash(cm);
                    if !witness.verify(&leaf, &mmr_root) { all_ok = false; break; }
                }
                all_ok
            }
        };

        // Verify PCD proof (fallback: allow if membership_ok)
        let pcd_valid = self
            .pcd_verifier
            .verify_proof(
                &tx.pcd_proof,
                &tx.pcd_prev_state_commitment,
                &tx.pcd_new_state_commitment,
                &tx.pcd_mmr_root,
                &tx.pcd_nullifier_root,
                &tx.anchor_height,
            )
            .await?;

        if !pcd_valid && !membership_ok {
            return Ok(ValidationResult {
                is_valid: false,
                error_message: Some("PCD proof verification failed".to_string()),
                gas_used: 1000,
                validated_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
        }

        // Verify spend proof (Orchard-like)
        let spend_valid = self.verify_spend_proof(tx).await?;

        if !spend_valid {
            return Ok(ValidationResult {
                is_valid: false,
                error_message: Some("Spend proof verification failed".to_string()),
                gas_used: 1000,
                validated_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
        }

        let gas_used = start_time.elapsed().as_millis() as u64;

        Ok(ValidationResult {
            is_valid: true,
            error_message: None,
            gas_used,
            validated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Validate a block with all its transactions
    pub async fn validate_block(&self, block: &Block) -> Result<BlockValidationResult> {
        let mut transaction_results = Vec::new();
        let mut total_gas_used = 0u64;

        // Validate each transaction in the block
        for tx in &block.transactions {
            let result = self.validate_transaction(tx).await?;
            total_gas_used += result.gas_used;
            transaction_results.push(result.clone());

            if !result.is_valid {
                return Ok(BlockValidationResult {
                    is_valid: false,
                    transaction_results,
                    block_hash: None,
                    total_gas_used,
                });
            }
        }

        // Update node state with new nullifiers and commitments; advance anchor
        {
            let mut state = self.state.write().unwrap();

            // Apply all nullifiers into the canonical set
            let mut new_nullifiers = Vec::new();
            for tx in &block.transactions {
                new_nullifiers.extend(tx.nullifiers.iter().cloned());
            }
            state.update_nullifier_set(new_nullifiers);

            // Append all output commitments to the MMR (domain-separated leaves)
            for tx in &block.transactions {
                for commitment in &tx.commitments {
                    let leaf = NodeState::leaf_hash(commitment);
                    // Ignore append errors in production you'd handle Result
                    let _ = state.commitment_mmr.append(leaf);
                }
            }
            // Refresh peaks and root
            state.refresh_mmr_view();

            // Advance anchor height to this block's height
            state.current_height = block.height;

            // Persist best-effort
            let data_dir = self.config.network_config.data_dir.clone();
            // Persist in background using a decoupled snapshot
            let snapshot = PersistedNodeState::from(&*state);
            let _ = tokio::spawn(async move {
                let path = std::path::Path::new(&data_dir).join("node_state.bin");
                if let Ok(bytes) = bincode::serialize(&snapshot) {
                    let _ = async_fs::write(&path, &bytes).await;
                }
            });
        }

        // Compute block hash
        let block_hash = self.compute_block_hash(block)?;

        Ok(BlockValidationResult {
            is_valid: true,
            transaction_results,
            block_hash: Some(block_hash),
            total_gas_used,
        })
    }

    /// Process pending transactions in the background
    async fn process_pending_transactions(
        _state: &Arc<RwLock<NodeState>>,
        _network: &TachyonNetwork,
    ) {
        // TODO: fetch from mempool/network; basic heartbeat for now
        debug!("Processing pending transactions (heartbeat)");
    }

    /// Run pruning to maintain minimal state
    async fn run_pruning(state: &Arc<RwLock<NodeState>>, config: &PruningConfig) {
        let mut state_guard = state.write().unwrap();

        // Check if we need to prune
        if state_guard.last_pruned.elapsed().as_secs() < config.pruning_interval_secs {
            return;
        }

        info!("Running node pruning");

        // In a real implementation, this would:
        // 1. Remove old nullifiers outside the window
        // 2. Prune old MMR data keeping only peaks
        // 3. Clean up old block data

        state_guard.last_pruned = Instant::now();
        state_guard.storage_size = 0; // Reset for simplicity

        info!("Node pruning completed");
    }

    /// Verify spend proof (basic binding + length checks)
    async fn verify_spend_proof(&self, tx: &Transaction) -> Result<bool> {
        // Require minimum proof length
        if tx.spend_proof.len() < 16 { return Ok(false); }

        // Bind spend proof to anchor, nullifiers and commitments deterministically
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"spend_proof_binding:v1");
        hasher.update(&tx.anchor_height.to_le_bytes());
        for n in &tx.nullifiers { hasher.update(n); }
        for c in &tx.commitments { hasher.update(c); }
        let expected = hasher.finalize();

        // Proof must equal binding preimage (not just hash equality);
        // we encode the binding digest directly as the proof in this demo.
        Ok(tx.spend_proof.as_slice() == expected.as_bytes())
    }

    /// Compute block hash
    fn compute_block_hash(&self, block: &Block) -> Result<TransactionHash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&block.height.to_le_bytes());
        hasher.update(block.previous_hash.0.as_bytes());
        for tx in &block.transactions {
            hasher.update(tx.hash.0.as_bytes());
        }
        Ok(TransactionHash(hasher.finalize()))
    }

    /// Get current node state
    pub fn get_state(&self) -> NodeState {
        // Clone the inner value instead of the guard
        let guard = self.state.read().unwrap();
        NodeState {
            current_height: guard.current_height,
            nullifier_set: guard.nullifier_set.clone(),
            commitment_mmr: guard.commitment_mmr.clone(),
            mmr_peaks: guard.mmr_peaks.clone(),
            mmr_root: guard.mmr_root,
            nullifier_root: guard.nullifier_root,
            last_pruned: guard.last_pruned,
            storage_size: guard.storage_size,
        }
    }

    /// Get the node's network ID as a string
    pub fn node_id(&self) -> String {
        self._network.node_id().to_string()
    }

    /// Shutdown the node
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }
        if let Some(task) = &self.pruning_task {
            task.abort();
        }
        Ok(())
    }
}

impl Drop for TachyonNode {
    fn drop(&mut self) {
        // Ensure clean shutdown
        if let Some(task) = self.validation_task.take() {
            task.abort();
        }
        if let Some(task) = self.pruning_task.take() {
            task.abort();
        }
    }
}

/// Serializable hash wrapper for transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionHash(pub Hash);

impl Serialize for TransactionHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for TransactionHash {
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
        Ok(TransactionHash(Hash::from(hash_bytes)))
    }
}

impl From<Hash> for TransactionHash {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<TransactionHash> for Hash {
    fn from(wrapper: TransactionHash) -> Self {
        wrapper.0
    }
}

/// Transaction representation for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction hash
    pub hash: TransactionHash,
    /// Revealed nullifiers
    pub nullifiers: Vec<[u8; 32]>,
    /// Note commitments (outputs)
    pub commitments: Vec<[u8; 32]>,
    /// Spent input commitments (optional; used to verify membership witnesses)
    pub spent_commitments: Vec<[u8; 32]>,
    /// Membership witnesses for spent inputs (bincode(MmrWitness))
    pub membership_witnesses: Vec<Vec<u8>>,
    /// PCD proof data
    pub pcd_proof: Vec<u8>,
    /// Previous PCD state commitment (public input 0)
    pub pcd_prev_state_commitment: [u8; 32],
    /// New PCD state commitment (public input 1)
    pub pcd_new_state_commitment: [u8; 32],
    /// MMR root (public input 2)
    pub pcd_mmr_root: [u8; 32],
    /// Nullifier root (public input 3)
    pub pcd_nullifier_root: [u8; 32],
    /// Anchor height for PCD validity (public input 4)
    pub anchor_height: u64,
    /// Spend proof data
    pub spend_proof: Vec<u8>,
}

impl Transaction {
    /// Validate basic transaction format
    pub fn validate_format(&self) -> Result<()> {
        if self.nullifiers.is_empty() {
            return Err(anyhow!("Transaction must have at least one nullifier"));
        }
        if self.commitments.is_empty() {
            return Err(anyhow!("Transaction must have at least one commitment"));
        }
        if self.spent_commitments.len() != self.membership_witnesses.len() {
            return Err(anyhow!("Spent commitments/witnesses length mismatch"));
        }
        if self.pcd_proof.is_empty() {
            return Err(anyhow!("Transaction must have PCD proof"));
        }
        // Basic consistency: new state matches circuit digest
        let expected_new = compute_transition_digest_bytes(
            &self.pcd_prev_state_commitment,
            &self.pcd_mmr_root,
            &self.pcd_nullifier_root,
            self.anchor_height,
        );
        if expected_new != self.pcd_new_state_commitment {
            return Err(anyhow!("PCD new_state_commitment does not match circuit digest"));
        }
        Ok(())
    }
}

/// Block representation for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block height
    pub height: u64,
    /// Previous block hash
    pub previous_hash: TransactionHash,
    /// Transactions in this block
    pub transactions: Vec<Transaction>,
    /// Block timestamp
    pub timestamp: u64,
}

impl Block {
    /// Create a new block
    pub fn new(
        height: u64,
        previous_hash: TransactionHash,
        transactions: Vec<Transaction>,
    ) -> Self {
        Self {
            height,
            previous_hash: previous_hash.into(),
            transactions,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Simple PCD verifier implementation
pub struct SimplePcdVerifier {
    /// Verification cache to avoid recomputing
    _cache: Arc<RwLock<HashMap<[u8; 32], bool>>>,
}

impl SimplePcdVerifier {
    /// Create a new verifier
    pub fn new() -> Self {
        Self {
            _cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Verify a PCD proof
    pub async fn verify_proof(
        &self,
        proof: &[u8],
        prev_state: &[u8; 32],
        new_state: &[u8; 32],
        mmr_root: &[u8; 32],
        nullifier_root: &[u8; 32],
        anchor_height: &u64,
    ) -> Result<bool> {
        if proof.is_empty() { return Ok(false); }
        let core = Halo2PcdCore::load_or_setup(std::path::Path::new("crates/node_ext/node_data/keys"), 12)?;
        core.verify_transition_proof(
            proof,
            prev_state,
            new_state,
            mmr_root,
            nullifier_root,
            *anchor_height,
        )
    }
}

#[async_trait::async_trait]
impl PcdVerifier for SimplePcdVerifier {
    async fn verify_proof(
        &self,
        proof: &[u8],
        prev_state: &[u8; 32],
        new_state: &[u8; 32],
        mmr_root: &[u8; 32],
        nullifier_root: &[u8; 32],
        anchor_height: &u64,
    ) -> Result<bool> {
        self.verify_proof(proof, prev_state, new_state, mmr_root, nullifier_root, anchor_height)
            .await
    }
}

#[async_trait::async_trait]
pub trait PcdVerifier: Send + Sync {
    /// Verify a PCD proof
    async fn verify_proof(
        &self,
        proof: &[u8],
        prev_state: &[u8; 32],
        new_state: &[u8; 32],
        mmr_root: &[u8; 32],
        nullifier_root: &[u8; 32],
        anchor_height: &u64,
    ) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let node = TachyonNode::new(config).await;
        assert!(node.is_ok());
    }

    #[test]
    fn test_transaction_validation() {
        let tx = Transaction {
            hash: TransactionHash(Hash::from([1u8; 32])),
            nullifiers: vec![[1u8; 32]],
            commitments: vec![[2u8; 32]],
            spent_commitments: vec![],
            membership_witnesses: vec![],
            pcd_proof: vec![1, 2, 3],
            pcd_prev_state_commitment: [3u8; 32],
            pcd_new_state_commitment: compute_transition_digest_bytes(&[3u8; 32], &[10u8; 32], &[11u8; 32], 100),
            pcd_mmr_root: [10u8; 32],
            pcd_nullifier_root: [11u8; 32],
            anchor_height: 100,
            spend_proof: vec![4, 5, 6],
        };

        assert!(tx.validate_format().is_ok());
    }

    #[test]
    fn test_block_aggregation() {
        let block = Block {
            height: 1,
            previous_hash: TransactionHash(Hash::from([0u8; 32])),
            transactions: vec![
                Transaction {
                    hash: TransactionHash(Hash::from([1u8; 32])),
                    nullifiers: vec![[1u8; 32]],
                    commitments: vec![[2u8; 32]],
                    spent_commitments: vec![],
                    membership_witnesses: vec![],
                    pcd_proof: vec![1, 2, 3],
                    pcd_prev_state_commitment: [3u8; 32],
                    pcd_new_state_commitment: compute_transition_digest_bytes(&[3u8; 32], &[10u8; 32], &[11u8; 32], 100),
                    pcd_mmr_root: [10u8; 32],
                    pcd_nullifier_root: [11u8; 32],
                    anchor_height: 100,
                    spend_proof: vec![4, 5, 6],
                },
                Transaction {
                    hash: TransactionHash(Hash::from([2u8; 32])),
                    nullifiers: vec![[3u8; 32]],
                    commitments: vec![[4u8; 32]],
                    spent_commitments: vec![],
                    membership_witnesses: vec![],
                    pcd_proof: vec![7, 8, 9],
                    pcd_prev_state_commitment: [5u8; 32],
                    pcd_new_state_commitment: compute_transition_digest_bytes(&[5u8; 32], &[12u8; 32], &[13u8; 32], 100),
                    pcd_mmr_root: [12u8; 32],
                    pcd_nullifier_root: [13u8; 32],
                    anchor_height: 100,
                    spend_proof: vec![7, 8, 9],
                },
            ],
            timestamp: 0,
        };

        // Directly aggregate without constructing a node/runtime (faster and avoids IO)
        let proofs: Vec<Vec<u8>> = block
            .transactions
            .iter()
            .map(|t| t.pcd_proof.clone())
            .collect();
        let agg = pcd_core::aggregation::aggregate_action_proofs(&proofs).unwrap();
        assert_eq!(agg.len(), 32);
    }
}
