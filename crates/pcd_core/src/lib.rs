//! # pcd_core
//!
//! Proof-carrying data (PCD) state management for Tachyon wallet.
//! Provides state definitions, proof interfaces, and recursion management.

use accum_mmr::{MmrAccumulator, MmrDelta};
use accum_set::{SetAccumulator, SetDelta};
use anyhow::{anyhow, Result};
use circuits::PcdCore as Halo2PcdCore;
use circuits::{aggregate_orchard_actions, compute_transition_digest_bytes};
use serde::{Deserialize, Serialize};
/// Type alias to reduce clippy-reported type complexity for persistence callback
pub type PersistenceCallback = Box<dyn Fn(&PcdState) -> Result<()> + Send + Sync>;

/// Size of PCD state commitment (BLAKE3 hash)
pub const PCD_STATE_COMMITMENT_SIZE: usize = 32;

/// Deprecated: was fixed-size; now proof size is dynamic per circuit backend
pub const PCD_PROOF_SIZE: usize = 32; // kept for tests/back-compat; not used in new flows

/// PCD state commitment
pub type PcdStateCommitment = [u8; PCD_STATE_COMMITMENT_SIZE];

/// Compute a deterministic binding proof for a state commitment (not a real ZK proof)
fn compute_state_proof(state_commitment: &PcdStateCommitment) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pcd_state_proof");
    hasher.update(state_commitment);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(hasher.finalize().as_bytes());
    proof
}

/// Compute a deterministic binding proof for a transition
fn compute_transition_proof(
    prev_state_commitment: &PcdStateCommitment,
    new_state_commitment: &PcdStateCommitment,
    mmr_delta: &[u8],
    nullifier_delta: &[u8],
    block_height_range: (u64, u64),
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pcd_transition_proof");
    hasher.update(prev_state_commitment);
    hasher.update(new_state_commitment);
    hasher.update(&block_height_range.0.to_le_bytes());
    hasher.update(&block_height_range.1.to_le_bytes());
    hasher.update(&(mmr_delta.len() as u32).to_le_bytes());
    hasher.update(mmr_delta);
    hasher.update(&(nullifier_delta.len() as u32).to_le_bytes());
    hasher.update(nullifier_delta);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(hasher.finalize().as_bytes());
    proof
}

/// PCD state representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcdState {
    /// Current anchor height
    pub anchor_height: u64,
    /// State commitment hash
    pub state_commitment: PcdStateCommitment,
    /// MMR root at anchor height
    pub mmr_root: [u8; 32],
    /// Nullifier set root at anchor height
    pub nullifier_root: [u8; 32],
    /// Block hash at anchor height
    pub block_hash: [u8; 32],
    /// PCD proof data
    pub proof: Vec<u8>,
    /// Additional state data (encrypted)
    pub state_data: Vec<u8>,
    /// Optional serialized MMR accumulator state
    pub mmr_bytes: Vec<u8>,
    /// Optional serialized nullifier set state
    pub nullifier_bytes: Vec<u8>,
}

impl PcdState {
    /// Create a new PCD state
    pub fn new(
        anchor_height: u64,
        mmr_root: [u8; 32],
        nullifier_root: [u8; 32],
        block_hash: [u8; 32],
        state_data: Vec<u8>,
        proof: Vec<u8>,
    ) -> Result<Self> {
        // Compute state commitment from all components
        let state_commitment = Self::compute_state_commitment(
            anchor_height,
            &mmr_root,
            &nullifier_root,
            &block_hash,
            &state_data,
        );

        Ok(Self {
            anchor_height,
            state_commitment,
            mmr_root,
            nullifier_root,
            block_hash,
            proof,
            state_data,
            mmr_bytes: Vec::new(),
            nullifier_bytes: Vec::new(),
        })
    }

    /// Compute state commitment hash
    pub fn compute_state_commitment(
        anchor_height: u64,
        mmr_root: &[u8; 32],
        nullifier_root: &[u8; 32],
        block_hash: &[u8; 32],
        state_data: &[u8],
    ) -> PcdStateCommitment {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pcd_state_commitment");
        hasher.update(&anchor_height.to_le_bytes());
        hasher.update(mmr_root);
        hasher.update(nullifier_root);
        hasher.update(block_hash);
        hasher.update(state_data);

        let mut commitment = [0u8; PCD_STATE_COMMITMENT_SIZE];
        commitment.copy_from_slice(hasher.finalize().as_bytes());
        commitment
    }

    /// Verify that this PCD state is consistent
    pub fn verify_consistency(&self) -> Result<()> {
        let computed_commitment = Self::compute_state_commitment(
            self.anchor_height,
            &self.mmr_root,
            &self.nullifier_root,
            &self.block_hash,
            &self.state_data,
        );

        if computed_commitment != self.state_commitment {
            return Err(anyhow!("PCD state commitment mismatch"));
        }

        Ok(())
    }

    /// Get the anchor height
    pub fn anchor_height(&self) -> u64 {
        self.anchor_height
    }

    /// Get the state commitment
    pub fn state_commitment(&self) -> &PcdStateCommitment {
        &self.state_commitment
    }

    /// Get the MMR root
    pub fn mmr_root(&self) -> &[u8; 32] {
        &self.mmr_root
    }

    /// Get the nullifier root
    pub fn nullifier_root(&self) -> &[u8; 32] {
        &self.nullifier_root
    }

    /// Get the block hash
    pub fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    /// Get the proof data
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Get the state data
    pub fn state_data(&self) -> &[u8] {
        &self.state_data
    }

    /// Get optional MMR accumulator bytes
    pub fn mmr_raw(&self) -> &[u8] {
        &self.mmr_bytes
    }

    /// Get optional nullifier bytes
    pub fn nullifier_raw(&self) -> &[u8] {
        &self.nullifier_bytes
    }
}

/// PCD transition data for updating state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcdTransition {
    /// Previous PCD state commitment
    pub prev_state_commitment: PcdStateCommitment,
    /// New PCD state commitment
    pub new_state_commitment: PcdStateCommitment,
    /// MMR delta being applied
    pub mmr_delta: Vec<u8>, // bincode of Vec<MmrDelta>
    /// Nullifier delta being applied (bincode(SetDelta or Vec<SetDelta>))
    pub nullifier_delta: Vec<u8>,
    /// Block height transition (prev -> new)
    pub block_height_range: (u64, u64),
    /// Transition proof data
    pub transition_proof: Vec<u8>,
}

impl PcdTransition {
    /// Create a new PCD transition
    pub fn new(
        prev_state: &PcdState,
        new_state: &PcdState,
        mmr_delta: Vec<u8>,
        nullifier_delta: Vec<u8>,
        transition_proof: Vec<u8>,
    ) -> Result<Self> {
        if prev_state.anchor_height >= new_state.anchor_height {
            return Err(anyhow!(
                "Invalid state transition: anchor height must increase"
            ));
        }

        Ok(Self {
            prev_state_commitment: prev_state.state_commitment,
            new_state_commitment: new_state.state_commitment,
            mmr_delta,
            nullifier_delta,
            block_height_range: (prev_state.anchor_height, new_state.anchor_height),
            transition_proof,
        })
    }

    /// Verify the transition is consistent
    pub fn verify(&self) -> Result<()> {
        // Basic structural verification; cryptographic proof checked elsewhere
        if self.prev_state_commitment == self.new_state_commitment {
            return Err(anyhow!("Transition must change state"));
        }

        Ok(())
    }

    /// Get previous state commitment
    pub fn prev_state_commitment(&self) -> &PcdStateCommitment {
        &self.prev_state_commitment
    }

    /// Get new state commitment
    pub fn new_state_commitment(&self) -> &PcdStateCommitment {
        &self.new_state_commitment
    }

    /// Get block height range
    pub fn block_height_range(&self) -> (u64, u64) {
        self.block_height_range
    }
}

/// PCD state machine for managing wallet state evolution
#[derive(Debug, Clone)]
pub struct PcdStateMachine {
    /// Current PCD state
    current_state: Option<PcdState>,
    /// State transition history for rollback support
    state_history: Vec<PcdState>,
    /// Maximum history size to prevent memory growth
    max_history_size: usize,
}

impl PcdStateMachine {
    /// Create a new PCD state machine
    pub fn new() -> Self {
        Self {
            current_state: None,
            state_history: Vec::new(),
            max_history_size: 100,
        }
    }

    /// Initialize with genesis state
    pub fn initialize_genesis(&mut self, genesis_state: PcdState) -> Result<()> {
        genesis_state.verify_consistency()?;
        self.current_state = Some(genesis_state.clone());
        self.state_history.push(genesis_state);
        Ok(())
    }

    /// Apply a state transition
    pub fn apply_transition(&mut self, transition: PcdTransition) -> Result<()> {
        transition.verify()?;

        // Verify transition connects to current state
        if let Some(current) = &self.current_state {
            if transition.prev_state_commitment != current.state_commitment {
                return Err(anyhow!("Transition does not connect to current state"));
            }
        } else {
            return Err(anyhow!("Cannot apply transition: no current state"));
        }

        // Create new state from transition
        let mut new_state = self.current_state.as_ref().unwrap().clone();
        new_state.anchor_height = transition.block_height_range.1;

        // Apply MMR deltas using accum_mmr
        if !transition.mmr_delta.is_empty() {
            // Deserialize accumulator or initialize
            let mut mmr: MmrAccumulator = if new_state.mmr_bytes.is_empty() {
                MmrAccumulator::new()
            } else {
                bincode::deserialize(&new_state.mmr_bytes).unwrap_or_else(|_| MmrAccumulator::new())
            };

            let deltas: Vec<MmrDelta> =
                bincode::deserialize(&transition.mmr_delta).unwrap_or_else(|_| Vec::new());
            mmr.apply_deltas(&deltas)?;
            if let Some(root) = mmr.root() {
                new_state.mmr_root = *root.as_bytes();
            }
            // Persist full MMR state into the PCD state for downstream witness updates
            new_state.mmr_bytes = bincode::serialize(&mmr).unwrap_or_default();
        }

        // Apply nullifier deltas using accum_set (supports batch operations)
        if !transition.nullifier_delta.is_empty() {
            // Deserialize accumulator or initialize
            let mut nullset: SetAccumulator = if new_state.nullifier_bytes.is_empty() {
                SetAccumulator::new()
            } else {
                bincode::deserialize(&new_state.nullifier_bytes)
                    .unwrap_or_else(|_| SetAccumulator::new())
            };

            // Support either a single SetDelta or Vec<SetDelta>
            let deltas: Vec<SetDelta> = match bincode::deserialize::<Vec<SetDelta>>(
                &transition.nullifier_delta,
            ) {
                Ok(v) => v,
                Err(_) => bincode::deserialize::<SetDelta>(&transition.nullifier_delta)
                    .map(|d| vec![d])
                    .unwrap_or_default(),
            };

            for d in deltas {
                nullset.apply_delta(d)?;
            }

            new_state.nullifier_root = nullset.root();
            // Persist full nullifier set state for consistency/auditing
            new_state.nullifier_bytes = bincode::serialize(&nullset).unwrap_or_default();
        }

        // Adopt the new commitment from the transition (authoritative)
        new_state.state_commitment = transition.new_state_commitment;

        // Verify Halo2 transition proof using circuit
        let halo2 = circuits::PcdCore::load_or_setup(
            std::path::Path::new("crates/node_ext/node_data/keys"),
            12,
        )?;
        let expected_new = compute_transition_digest_bytes(
            &transition.prev_state_commitment,
            &new_state.mmr_root,
            &new_state.nullifier_root,
            new_state.anchor_height,
        );
        if !halo2.verify_transition_proof(
            &transition.transition_proof,
            &transition.prev_state_commitment,
            &expected_new,
            &new_state.mmr_root,
            &new_state.nullifier_root,
            new_state.anchor_height,
        )? {
            return Err(anyhow!("Halo2 transition proof verification failed"));
        }

        // Generate a circuit-backed proof bytes using Halo2 mock prover (placeholder backend)
        let halo2 = circuits::PcdCore::load_or_setup(
            std::path::Path::new("crates/node_ext/node_data/keys"),
            12,
        )?;
        let new_digest = compute_transition_digest_bytes(
            &transition.prev_state_commitment,
            &new_state.mmr_root,
            &new_state.nullifier_root,
            new_state.anchor_height,
        );
        let proof_bytes = halo2.prove_transition(
            &transition.prev_state_commitment,
            &new_digest,
            &new_state.mmr_root,
            &new_state.nullifier_root,
            new_state.anchor_height,
        )?;
        new_state.proof = proof_bytes;

        // Update state and history
        self.current_state = Some(new_state.clone());

        if self.state_history.len() >= self.max_history_size {
            self.state_history.remove(0); // Remove oldest state
        }
        self.state_history.push(new_state);

        Ok(())
    }

    /// Get current PCD state
    pub fn current_state(&self) -> Option<&PcdState> {
        self.current_state.as_ref()
    }

    /// Get state at specific height (from history)
    pub fn state_at_height(&self, height: u64) -> Option<&PcdState> {
        self.state_history
            .iter()
            .find(|state| state.anchor_height == height)
    }

    /// Rollback to a previous state
    pub fn rollback_to_height(&mut self, height: u64) -> Result<()> {
        if let Some(target_state) = self.state_at_height(height).cloned() {
            // Remove all states after target height
            let target_index = self
                .state_history
                .iter()
                .position(|s| s.anchor_height == height)
                .unwrap();
            self.state_history.truncate(target_index + 1);
            self.current_state = Some(target_state);
            Ok(())
        } else {
            Err(anyhow!(
                "Cannot rollback: state at height {} not found",
                height
            ))
        }
    }

    /// Get current anchor height
    pub fn current_anchor_height(&self) -> Option<u64> {
        self.current_state.as_ref().map(|s| s.anchor_height)
    }

    /// Get state history length
    pub fn history_length(&self) -> usize {
        self.state_history.len()
    }
}

impl Default for PcdStateMachine {
    fn default() -> Self { Self::new() }
}

/// PCD proof verification interface
pub trait PcdProofVerifier {
    /// Verify a PCD state proof
    fn verify_state_proof(&self, state: &PcdState) -> Result<bool>;

    /// Verify a PCD transition proof
    fn verify_transition_proof(&self, transition: &PcdTransition) -> Result<bool>;

    /// Generate a proof for a PCD state (placeholder for future implementation)
    fn generate_state_proof(&self, state: &PcdState) -> Result<Vec<u8>>;

    /// Generate a proof for a PCD transition (placeholder for future implementation)
    fn generate_transition_proof(&self, transition: &PcdTransition) -> Result<Vec<u8>>;
}

/// Simple PCD proof verifier (placeholder implementation)
pub struct SimplePcdVerifier;

impl PcdProofVerifier for SimplePcdVerifier {
    fn verify_state_proof(&self, state: &PcdState) -> Result<bool> {
        // Prefer circuit-backed verification
        if !state.proof.is_empty() {
            let halo2 = circuits::PcdCore::load_or_setup(
                std::path::Path::new("crates/node_ext/node_data/keys"),
                12,
            )?;
            let expected_new = compute_transition_digest_bytes(
                &state.state_commitment,
                &state.mmr_root,
                &state.nullifier_root,
                state.anchor_height,
            );
            if halo2.verify_transition_proof(
                &state.proof,
                &state.state_commitment,
                &expected_new,
                &state.mmr_root,
                &state.nullifier_root,
                state.anchor_height,
            )? {
                return Ok(true);
            }
        }

        // Fallback to legacy hash-binding for backward compatibility
        let expected_proof = compute_state_proof(&state.state_commitment);
        Ok(state.proof.as_slice() == expected_proof.as_slice())
    }

    fn verify_transition_proof(&self, transition: &PcdTransition) -> Result<bool> {
        if transition.transition_proof.is_empty() {
            return Ok(false);
        }

        // Validate legacy binding hash for transition integrity
        let expected = compute_transition_proof(
            &transition.prev_state_commitment,
            &transition.new_state_commitment,
            &transition.mmr_delta,
            &transition.nullifier_delta,
            transition.block_height_range,
        );
        Ok(transition.transition_proof.as_slice() == expected)
    }

    fn generate_state_proof(&self, state: &PcdState) -> Result<Vec<u8>> {
        let halo2 = Halo2PcdCore::new()?;
        let new_digest = compute_transition_digest_bytes(
            &state.state_commitment,
            &state.mmr_root,
            &state.nullifier_root,
            state.anchor_height,
        );
        halo2.prove_transition(
            &state.state_commitment,
            &new_digest,
            &state.mmr_root,
            &state.nullifier_root,
            state.anchor_height,
        )
    }

    fn generate_transition_proof(&self, transition: &PcdTransition) -> Result<Vec<u8>> {
        let halo2 = Halo2PcdCore::new()?;
        // Bind to delta commitments (32-byte) inside the circuit
        let mmr_commitment = blake3::hash(&transition.mmr_delta);
        let nullifier_commitment = blake3::hash(&transition.nullifier_delta);
        let new_digest = compute_transition_digest_bytes(
            &transition.prev_state_commitment,
            mmr_commitment.as_bytes(),
            nullifier_commitment.as_bytes(),
            transition.block_height_range.1,
        );
        halo2.prove_transition(
            &transition.prev_state_commitment,
            &new_digest,
            mmr_commitment.as_bytes(),
            nullifier_commitment.as_bytes(),
            transition.block_height_range.1,
        )
    }
}

/// PCD state manager with verification and persistence
pub struct PcdStateManager<V: PcdProofVerifier> {
    /// State machine
    state_machine: PcdStateMachine,
    /// Proof verifier
    verifier: V,
    /// State persistence callback
    persistence_callback: Option<PersistenceCallback>,
}

impl<V: PcdProofVerifier> PcdStateManager<V> {
    /// Create a new PCD state manager
    pub fn new(verifier: V) -> Self {
        Self {
            state_machine: PcdStateMachine::new(),
            verifier,
            persistence_callback: None,
        }
    }

    /// Set persistence callback for state changes
    pub fn set_persistence_callback<F>(&mut self, callback: F)
    where
        F: Fn(&PcdState) -> Result<()> + Send + Sync + 'static,
    {
        self.persistence_callback = Some(Box::new(callback));
    }

    /// Initialize with genesis state
    pub fn initialize_genesis(&mut self, genesis_state: PcdState) -> Result<()> {
        // Verify genesis state proof
        if !self.verifier.verify_state_proof(&genesis_state)? {
            return Err(anyhow!("Invalid genesis state proof"));
        }

        self.state_machine
            .initialize_genesis(genesis_state.clone())?;

        // Persist genesis state
        if let Some(callback) = &self.persistence_callback {
            callback(&genesis_state)?;
        }

        Ok(())
    }

    /// Apply a state transition with verification
    pub fn apply_transition(&mut self, transition: PcdTransition) -> Result<()> {
        // Verify transition proof
        if !self.verifier.verify_transition_proof(&transition)? {
            return Err(anyhow!("Invalid transition proof"));
        }

        self.state_machine.apply_transition(transition.clone())?;

        // Persist new state
        if let Some(current_state) = &self.state_machine.current_state {
            if let Some(callback) = &self.persistence_callback {
                callback(current_state)?;
            }
        }

        Ok(())
    }

    /// Get current PCD state
    pub fn current_state(&self) -> Option<&PcdState> {
        self.state_machine.current_state()
    }

    /// Get state machine reference
    pub fn state_machine(&self) -> &PcdStateMachine {
        &self.state_machine
    }

    /// Verify current state consistency
    pub fn verify_current_state(&self) -> Result<()> {
        if let Some(state) = self.current_state() {
            state.verify_consistency()?;
            if !self.verifier.verify_state_proof(state)? {
                return Err(anyhow!("Current state proof verification failed"));
            }
        }
        Ok(())
    }
}

/// Aggregation helpers for wallet and node
pub mod aggregation {
    use super::*;

    /// Aggregate multiple Orchard-like action proofs into one proof blob
    pub fn aggregate_action_proofs(action_proofs: &[Vec<u8>]) -> Result<Vec<u8>> {
        aggregate_orchard_actions(action_proofs)
    }
}

/// PCD delta bundle for batched state updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcdDeltaBundle {
    /// MMR deltas
    pub mmr_deltas: Vec<Vec<u8>>,
    /// Nullifier deltas
    pub nullifier_deltas: Vec<Vec<u8>>,
    /// Block height range
    pub block_range: (u64, u64),
    /// Delta bundle hash for integrity
    pub bundle_hash: [u8; 32],
}

impl PcdDeltaBundle {
    /// Create a new delta bundle
    pub fn new(
        mmr_deltas: Vec<Vec<u8>>,
        nullifier_deltas: Vec<Vec<u8>>,
        block_range: (u64, u64),
    ) -> Self {
        // Compute bundle hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pcd_delta_bundle");
        hasher.update(&block_range.0.to_le_bytes());
        hasher.update(&block_range.1.to_le_bytes());

        for delta in &mmr_deltas {
            hasher.update(&(delta.len() as u32).to_le_bytes());
            hasher.update(delta);
        }

        for delta in &nullifier_deltas {
            hasher.update(&(delta.len() as u32).to_le_bytes());
            hasher.update(delta);
        }

        let mut bundle_hash = [0u8; 32];
        bundle_hash.copy_from_slice(hasher.finalize().as_bytes());

        Self {
            mmr_deltas,
            nullifier_deltas,
            block_range,
            bundle_hash,
        }
    }

    /// Verify bundle integrity
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"pcd_delta_bundle");
            hasher.update(&self.block_range.0.to_le_bytes());
            hasher.update(&self.block_range.1.to_le_bytes());

            for delta in &self.mmr_deltas {
                hasher.update(&(delta.len() as u32).to_le_bytes());
                hasher.update(delta);
            }

            for delta in &self.nullifier_deltas {
                hasher.update(&(delta.len() as u32).to_le_bytes());
                hasher.update(delta);
            }

            hasher.finalize()
        };

        computed_hash.as_bytes() == &self.bundle_hash
    }

    /// Get MMR deltas
    pub fn mmr_deltas(&self) -> &[Vec<u8>] {
        &self.mmr_deltas
    }

    /// Get nullifier deltas
    pub fn nullifier_deltas(&self) -> &[Vec<u8>] {
        &self.nullifier_deltas
    }

    /// Get block range
    pub fn block_range(&self) -> (u64, u64) {
        self.block_range
    }
}

/// PCD state synchronization client interface
pub trait PcdSyncClient {
    /// Fetch PCD state for a specific height
    fn fetch_state(
        &self,
        height: u64,
    ) -> impl std::future::Future<Output = Result<Option<PcdState>>> + Send;

    /// Fetch delta bundle for a height range
    fn fetch_delta_bundle(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> impl std::future::Future<Output = Result<Option<PcdDeltaBundle>>> + Send;

    /// Fetch transition proof for a state transition
    fn fetch_transition_proof(
        &self,
        prev_height: u64,
        new_height: u64,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send;
}

/// PCD state synchronization manager
pub struct PcdSyncManager<C: PcdSyncClient, V: PcdProofVerifier> {
    /// Sync client
    client: C,
    /// State manager
    state_manager: PcdStateManager<V>,
}

impl<C: PcdSyncClient, V: PcdProofVerifier> PcdSyncManager<C, V> {
    /// Create a new sync manager
    pub fn new(client: C, verifier: V) -> Self {
        Self {
            client,
            state_manager: PcdStateManager::new(verifier),
        }
    }

    /// Initialize the internal state manager with an existing state (e.g., from storage)
    pub fn initialize_with_state(&mut self, state: PcdState) -> Result<()> {
        self.state_manager.initialize_genesis(state)
    }

    /// Set a persistence callback invoked whenever the internal state changes
    pub fn set_persistence_callback<F>(&mut self, callback: F)
    where
        F: Fn(&PcdState) -> Result<()> + Send + Sync + 'static,
    {
        self.state_manager.set_persistence_callback(callback);
    }

    /// Sync to a target height
    pub async fn sync_to_height(&mut self, target_height: u64) -> Result<()> {
        let current_height = self
            .state_manager
            .current_state()
            .map(|s| s.anchor_height)
            .unwrap_or(0);

        if target_height <= current_height {
            return Ok(()); // Already at or beyond target
        }

        // Fetch delta bundle for the range
        if let Some(delta_bundle) = self
            .client
            .fetch_delta_bundle(current_height, target_height)
            .await?
        {
            if !delta_bundle.verify_integrity() {
                return Err(anyhow!("Delta bundle integrity check failed"));
            }
            // Require a current state to anchor the transition
            let Some(prev_state) = self.state_manager.current_state().cloned() else {
                return Ok(());
            };

            // Aggregate MMR deltas from segments into a single Vec<MmrDelta>
            let mut mmr_ops: Vec<MmrDelta> = Vec::new();
            for seg in &delta_bundle.mmr_deltas {
                if let Ok(mut ops) = bincode::deserialize::<Vec<MmrDelta>>(seg) {
                    mmr_ops.append(&mut ops);
                }
            }
            let mmr_delta_bytes = bincode::serialize(&mmr_ops)?;

            // Aggregate nullifier deltas into a single Vec<SetDelta>
            let mut nf_ops: Vec<SetDelta> = Vec::new();
            for seg in &delta_bundle.nullifier_deltas {
                if let Ok(mut ops) = bincode::deserialize::<Vec<SetDelta>>(seg) {
                    nf_ops.append(&mut ops);
                } else if let Ok(op) = bincode::deserialize::<SetDelta>(seg) {
                    nf_ops.push(op);
                }
            }
            let nullifier_delta_bytes = bincode::serialize(&nf_ops)?;

            // Derive new roots deterministically from aggregated deltas (mirrors OSS)
            let new_mmr_root = *blake3::hash(&mmr_delta_bytes).as_bytes();
            let new_nf_root = *blake3::hash(&nullifier_delta_bytes).as_bytes();

            // Advance height to bundle end and bind state to bundle hash
            let new_height = delta_bundle.block_range.1;
            let mut new_state_data = prev_state.state_data.clone();
            new_state_data.extend_from_slice(&delta_bundle.bundle_hash);

            // Compute new state commitment and proof
            let new_commitment = PcdState::compute_state_commitment(
                new_height,
                &new_mmr_root,
                &new_nf_root,
                &prev_state.block_hash,
                &new_state_data,
            );
            let new_state_proof = compute_state_proof(&new_commitment).to_vec();
            let new_state = PcdState::new(
                new_height,
                new_mmr_root,
                new_nf_root,
                prev_state.block_hash,
                new_state_data,
                new_state_proof,
            )?;

            // Compute binding transition proof over commitments and aggregated deltas
            let transition_proof = compute_transition_proof(
                &prev_state.state_commitment,
                &new_state.state_commitment,
                &mmr_delta_bytes,
                &nullifier_delta_bytes,
                (prev_state.anchor_height, new_height),
            )
            .to_vec();

            let transition = PcdTransition::new(
                &prev_state,
                &new_state,
                mmr_delta_bytes,
                nullifier_delta_bytes,
                transition_proof,
            )?;

            // Apply the transition
            self.state_manager.apply_transition(transition)?;
        } else {
            // Fall back to incremental sync if no bundle available
            for height in (current_height + 1)..=target_height {
                if let Some(fetched_state) = self.client.fetch_state(height).await? {
                    // If we have no current state yet, initialize with fetched genesis
                    if self.state_manager.current_state().is_none() {
                        let _ = self.state_manager.initialize_genesis(fetched_state.clone());
                        continue;
                    }

                    let prev_state = match self.state_manager.current_state() {
                        Some(s) => s.clone(),
                        None => continue,
                    };

                    // Without explicit deltas, advance height with empty deltas and preserve roots
                    let new_height = height;
                    let mmr_delta_bytes: Vec<u8> = Vec::new();
                    let nullifier_delta_bytes: Vec<u8> = Vec::new();

                    let mut new_state_data = prev_state.state_data.clone();
                    // Bind to fetched state's commitment bytes to avoid stalling (non-critical)
                    new_state_data.extend_from_slice(&fetched_state.state_commitment);

                    let new_commitment = PcdState::compute_state_commitment(
                        new_height,
                        &prev_state.mmr_root,
                        &prev_state.nullifier_root,
                        &prev_state.block_hash,
                        &new_state_data,
                    );
                    let new_state_proof = compute_state_proof(&new_commitment).to_vec();
                    let new_state = PcdState::new(
                        new_height,
                        prev_state.mmr_root,
                        prev_state.nullifier_root,
                        prev_state.block_hash,
                        new_state_data,
                        new_state_proof,
                    )?;

                    let transition_proof = compute_transition_proof(
                        &prev_state.state_commitment,
                        &new_state.state_commitment,
                        &mmr_delta_bytes,
                        &nullifier_delta_bytes,
                        (prev_state.anchor_height, new_height),
                    )
                    .to_vec();

                    let transition = PcdTransition::new(
                        &prev_state,
                        &new_state,
                        mmr_delta_bytes,
                        nullifier_delta_bytes,
                        transition_proof,
                    )?;

                    self.state_manager.apply_transition(transition)?;
                }
            }
        }

        Ok(())
    }

    /// Get current state manager
    pub fn state_manager(&self) -> &PcdStateManager<V> {
        &self.state_manager
    }

    /// Get sync client reference
    pub fn client(&self) -> &C {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcd_state_creation() {
        let mmr_root = [1u8; 32];
        let nullifier_root = [2u8; 32];
        let block_hash = [3u8; 32];
        let state_data = b"test state data".to_vec();
        let provisional = PcdState::new(
            100,
            mmr_root,
            nullifier_root,
            block_hash,
            state_data,
            vec![],
        )
        .unwrap();
        let proof = compute_state_proof(&provisional.state_commitment).to_vec();
        let state = PcdState::new(
            100,
            mmr_root,
            nullifier_root,
            block_hash,
            provisional.state_data.clone(),
            proof,
        )
        .unwrap();

        assert_eq!(state.anchor_height, 100);
        assert_ne!(state.state_commitment, [0u8; 32]);
        assert_eq!(state.mmr_root, mmr_root);
        assert_eq!(state.nullifier_root, nullifier_root);
        assert_eq!(state.block_hash, block_hash);
    }

    #[test]
    fn test_pcd_state_consistency() {
        let mmr_root = [1u8; 32];
        let nullifier_root = [2u8; 32];
        let block_hash = [3u8; 32];
        let state_data = b"test state data".to_vec();
        let provisional = PcdState::new(
            100,
            mmr_root,
            nullifier_root,
            block_hash,
            state_data.clone(),
            vec![],
        )
        .unwrap();
        let proof = compute_state_proof(&provisional.state_commitment).to_vec();
        let state = PcdState::new(
            100,
            mmr_root,
            nullifier_root,
            block_hash,
            state_data.clone(),
            proof,
        )
        .unwrap();
        state.verify_consistency().unwrap();

        // Test with modified state data (should fail consistency check)
        let mut bad_state = state.clone();
        bad_state.state_data = b"modified data".to_vec();
        assert!(bad_state.verify_consistency().is_err());
    }

    #[test]
    fn test_pcd_transition() {
        let prev_state_data = b"prev state".to_vec();
        let new_state_data = b"new state".to_vec();

        let prev_state = {
            let provisional = PcdState::new(
                100,
                [1u8; 32],
                [2u8; 32],
                [3u8; 32],
                prev_state_data,
                vec![],
            )
            .unwrap();
            let proof = compute_state_proof(&provisional.state_commitment).to_vec();
            PcdState::new(
                100,
                provisional.mmr_root,
                provisional.nullifier_root,
                provisional.block_hash,
                provisional.state_data.clone(),
                proof,
            )
            .unwrap()
        };

        let new_state = {
            let provisional =
                PcdState::new(101, [4u8; 32], [5u8; 32], [6u8; 32], new_state_data, vec![])
                    .unwrap();
            let proof = compute_state_proof(&provisional.state_commitment).to_vec();
            PcdState::new(
                101,
                provisional.mmr_root,
                provisional.nullifier_root,
                provisional.block_hash,
                provisional.state_data.clone(),
                proof,
            )
            .unwrap()
        };

        let mmr_delta = b"mmr delta".to_vec();
        let nullifier_delta = b"nullifier delta".to_vec();
        let transition_proof = compute_transition_proof(
            &prev_state.state_commitment,
            &new_state.state_commitment,
            &mmr_delta,
            &nullifier_delta,
            (100, 101),
        )
        .to_vec();

        let transition = PcdTransition::new(
            &prev_state,
            &new_state,
            mmr_delta,
            nullifier_delta,
            transition_proof,
        )
        .unwrap();

        assert_eq!(transition.block_height_range, (100, 101));
        assert_eq!(
            transition.prev_state_commitment,
            prev_state.state_commitment
        );
        assert_eq!(transition.new_state_commitment, new_state.state_commitment);
    }

    #[test]
    fn test_state_machine() {
        let mut state_machine = PcdStateMachine::new();

        let genesis_state = {
            let provisional = PcdState::new(
                0,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
                b"genesis".to_vec(),
                vec![],
            )
            .unwrap();
            let proof = compute_state_proof(&provisional.state_commitment).to_vec();
            PcdState::new(
                0,
                provisional.mmr_root,
                provisional.nullifier_root,
                provisional.block_hash,
                provisional.state_data.clone(),
                proof,
            )
            .unwrap()
        };

        state_machine
            .initialize_genesis(genesis_state.clone())
            .unwrap();
        assert_eq!(state_machine.current_anchor_height(), Some(0));
        assert_eq!(state_machine.history_length(), 1);

        // Add another state; since we use empty deltas, roots/hash must match genesis
        let next_state = {
            let provisional = PcdState::new(
                1,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
                b"state 1".to_vec(),
                vec![],
            )
            .unwrap();
            let proof = compute_state_proof(&provisional.state_commitment).to_vec();
            PcdState::new(
                1,
                provisional.mmr_root,
                provisional.nullifier_root,
                provisional.block_hash,
                provisional.state_data.clone(),
                proof,
            )
            .unwrap()
        };

        let transition = PcdTransition::new(
            &genesis_state,
            &next_state,
            vec![],
            vec![],
            compute_transition_proof(
                &genesis_state.state_commitment,
                &next_state.state_commitment,
                &[],
                &[],
                (0, 1),
            )
            .to_vec(),
        )
        .unwrap();

        state_machine.apply_transition(transition).unwrap();
        assert_eq!(state_machine.current_anchor_height(), Some(1));
        assert_eq!(state_machine.history_length(), 2);

        // Test rollback
        state_machine.rollback_to_height(0).unwrap();
        assert_eq!(state_machine.current_anchor_height(), Some(0));
        assert_eq!(state_machine.history_length(), 1);
    }

    #[test]
    fn test_delta_bundle() {
        let mmr_deltas = vec![b"delta1".to_vec(), b"delta2".to_vec()];
        let nullifier_deltas = vec![b"nf_delta1".to_vec()];
        let bundle = PcdDeltaBundle::new(mmr_deltas.clone(), nullifier_deltas.clone(), (100, 200));

        assert!(bundle.verify_integrity());
        assert_eq!(bundle.mmr_deltas().len(), 2);
        assert_eq!(bundle.nullifier_deltas().len(), 1);
        assert_eq!(bundle.block_range(), (100, 200));
    }

    #[test]
    fn test_state_manager() {
        let verifier = SimplePcdVerifier;
        let mut state_manager = PcdStateManager::new(verifier);

        let genesis_state = {
            let provisional = PcdState::new(
                0,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
                b"genesis".to_vec(),
                vec![],
            )
            .unwrap();
            let proof = compute_state_proof(&provisional.state_commitment).to_vec();
            PcdState::new(
                0,
                provisional.mmr_root,
                provisional.nullifier_root,
                provisional.block_hash,
                provisional.state_data.clone(),
                proof,
            )
            .unwrap()
        };

        state_manager
            .initialize_genesis(genesis_state.clone())
            .unwrap();
        assert!(state_manager.current_state().is_some());

        state_manager.verify_current_state().unwrap();
    }
}
