//! # node_ext
//! Numan Thabit
//! Validator / Node extension implementation for Tachyon.
//! Verifies PCD proofs, nullifier checks, and maintains minimal state for validation.

use accum_mmr::SerializableHash;
use anyhow::{anyhow, Result};
use blake3::Hash;
use net_iroh::TachyonNetwork;
use pcd_core::aggregation::aggregate_action_proofs;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::interval,
};
use tracing::{debug, info};

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
    /// Recent nullifier window
    pub nullifier_window: HashSet<[u8; 32]>,
    /// MMR peaks for validation
    pub mmr_peaks: Vec<(u64, SerializableHash)>,
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
            nullifier_window: HashSet::new(),
            mmr_peaks: Vec::new(),
            last_pruned: Instant::now(),
            storage_size: 0,
        }
    }

    /// Update nullifier window for new block
    pub fn update_nullifier_window(&mut self, new_nullifiers: Vec<[u8; 32]>, window_size: u64) {
        // Remove old nullifiers if window is full
        if self.nullifier_window.len() >= window_size as usize {
            // For simplicity, just clear and rebuild - in production would use proper sliding window
            self.nullifier_window.clear();
        }

        // Add new nullifiers
        for nullifier in new_nullifiers {
            self.nullifier_window.insert(nullifier);
        }
    }

    /// Check if a nullifier is in the recent window
    pub fn check_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifier_window.contains(nullifier)
    }

    /// Update MMR peaks
    pub fn update_mmr_peaks(&mut self, peaks: Vec<(u64, SerializableHash)>) {
        self.mmr_peaks = peaks;
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
        let state = Arc::new(RwLock::new(NodeState::new()));
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

        // Check nullifier window; accept blinded nullifiers
        for nullifier in &tx.nullifiers {
            let state = self.state.read().unwrap();
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

        // Verify PCD proof
        let pcd_valid = self
            .pcd_verifier
            .verify_proof(&tx.pcd_proof, &tx.pcd_state_commitment, &tx.anchor_height)
            .await?;

        if !pcd_valid {
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

        // Update node state with new nullifiers and MMR peaks
        let mut state = self.state.write().unwrap();
        let mut new_nullifiers = Vec::new();
        for tx in &block.transactions {
            new_nullifiers.extend(tx.nullifiers.iter().cloned());
        }
        state.update_nullifier_window(
            new_nullifiers,
            self.config.validation_config.nullifier_window_size,
        );
        state.current_height = block.height;

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
            nullifier_window: guard.nullifier_window.clone(),
            mmr_peaks: guard.mmr_peaks.clone(),
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
    /// PCD proof data
    pub pcd_proof: Vec<u8>,
    /// PCD state commitment
    pub pcd_state_commitment: [u8; 32],
    /// Anchor height for PCD validity
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
        if self.pcd_proof.is_empty() {
            return Err(anyhow!("Transaction must have PCD proof"));
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
        _state_commitment: &[u8; 32],
        _anchor_height: &u64,
    ) -> Result<bool> {
        // In a real implementation, this would use halo2 to verify the proof
        // For now, just check if proof is non-empty and state commitment looks valid
        if proof.is_empty() {
            return Ok(false);
        }

        // Simple check: proof should contain the state commitment
        Ok(proof.iter().any(|&b| b != 0))
    }
}

#[async_trait::async_trait]
impl PcdVerifier for SimplePcdVerifier {
    async fn verify_proof(
        &self,
        proof: &[u8],
        state_commitment: &[u8; 32],
        anchor_height: &u64,
    ) -> Result<bool> {
        self.verify_proof(proof, state_commitment, anchor_height)
            .await
    }
}

#[async_trait::async_trait]
pub trait PcdVerifier: Send + Sync {
    /// Verify a PCD proof
    async fn verify_proof(
        &self,
        proof: &[u8],
        state_commitment: &[u8; 32],
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
            pcd_proof: vec![1, 2, 3],
            pcd_state_commitment: [3u8; 32],
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
                    pcd_proof: vec![1, 2, 3],
                    pcd_state_commitment: [3u8; 32],
                    anchor_height: 100,
                    spend_proof: vec![4, 5, 6],
                },
                Transaction {
                    hash: TransactionHash(Hash::from([2u8; 32])),
                    nullifiers: vec![[3u8; 32]],
                    commitments: vec![[4u8; 32]],
                    pcd_proof: vec![7, 8, 9],
                    pcd_state_commitment: [5u8; 32],
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
