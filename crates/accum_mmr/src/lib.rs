//! # accum_mmr
//!
//! Merkle Mountain Range (MMR) accumulator implementation for Tachyon.
//! Provides append-only structure with proof generation, delta application, and witness updates.

use anyhow::anyhow;
use crate::error::Result;
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

/// Size of MMR nodes in bytes
pub const MMR_NODE_SIZE: usize = 32;
pub mod error {
    use thiserror::Error as ThisError;
    pub type Result<T> = core::result::Result<T, Error>;
    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("invalid input: {0}")] InvalidInput(String),
        #[error("missing data: {0}")] Missing(String),
        #[error("serialize error: {0}")] Serialize(String),
        #[error("deserialize error: {0}")] Deserialize(String),
        #[error("other: {0}")] Other(String),
    }
    impl From<anyhow::Error> for Error { fn from(e: anyhow::Error) -> Self { Error::Other(e.to_string()) } }
}


/// Wrapper for Hash that implements Serialize/Deserialize
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SerializableHash(pub Hash);

impl SerializableHash {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Serialize for SerializableHash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for SerializableHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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

/// Hashing utilities for MMR nodes
fn mmr_hash_parent(left: &Hash, right: &Hash) -> Hash {
    // Domain-separated hashing for inner nodes to avoid ambiguity
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mmr:node:v1");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

/// Position arithmetic helpers for MMR (post-order indexing)
fn mmr_height(pos: u64) -> u32 {
    (!pos).trailing_zeros()
}
fn mmr_is_right_child(pos: u64) -> bool {
    let h = mmr_height(pos);
    mmr_height(pos + 1) == h + 1
}
fn mmr_sibling_pos(pos: u64) -> u64 {
    let h = mmr_height(pos);
    if mmr_is_right_child(pos) {
        pos.saturating_sub(1u64 << h)
    } else {
        pos + (1u64 << h)
    }
}
fn mmr_parent_pos(pos: u64) -> u64 {
    let h = mmr_height(pos);
    if mmr_is_right_child(pos) {
        pos + 1
    } else {
        pos + (1u64 << h) + 1
    }
}

/// MMR node representation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MmrNode {
    /// The hash value of this node
    pub hash: SerializableHash,
    /// Position in the MMR (0-based)
    pub position: u64,
}

impl MmrNode {
    /// Create a new MMR node
    pub fn new(hash: Hash, position: u64) -> Self {
        Self {
            hash: SerializableHash(hash),
            position,
        }
    }

    /// Get the height of this node in the MMR tree
    pub fn height(&self) -> u32 {
        (!self.position).trailing_zeros()
    }

    /// Get the peak position for this node's mountain
    pub fn mountain_peak(&self) -> u64 {
        let height = self.height();
        (1u64 << (height + 1)) - 2
    }

    /// Check if this is a peak node
    pub fn is_peak(&self) -> bool {
        let height = self.height();
        let next_height = height + 1;
        let next_peak = (1u64 << next_height) - 2;
        self.position == next_peak
    }

    /// Get the underlying hash
    pub fn hash(&self) -> Hash {
        self.hash.0
    }
}

impl fmt::Display for MmrNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Node(pos={}, hash={})",
            self.position,
            hex::encode(self.hash.0.as_bytes())
        )
    }
}

/// MMR proof for a specific element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrProof {
    /// The element being proven
    pub element: MmrNode,
    /// Sibling nodes needed for verification
    pub siblings: Vec<MmrNode>,
    /// Peak nodes for the mountain
    pub peaks: Vec<MmrNode>,
}

impl MmrProof {
    /// Verify this proof against the given root hash
    pub fn verify(&self, expected_root: &Hash) -> bool {
        self.calculate_root() == *expected_root
    }

    /// Calculate the root hash from this proof
    pub fn calculate_root(&self) -> Hash {
        // Recompute the peak hash for the element's mountain using siblings (bottom-up),
        // then bag with the other peaks from right to left.
        let mut current_hash = self.element.hash.0;
        let mut current_pos = self.element.position;

        for sib in &self.siblings {
            let (left, right) = if sib.position < current_pos {
                (sib.hash.0, current_hash)
            } else {
                (current_hash, sib.hash.0)
            };
            current_hash = mmr_hash_parent(&left, &right);
            current_pos = mmr_parent_pos(current_pos);
        }

        // Bag peaks from right to left, substituting the computed mountain peak
        let mut acc: Option<Hash> = None;
        for peak in self.peaks.iter().rev() {
            let peak_hash = if peak.position == current_pos {
                current_hash
            } else {
                peak.hash.0
            };
            acc = Some(match acc {
                None => peak_hash,
                Some(r) => mmr_hash_parent(&peak_hash, &r),
            });
        }

        // MMR proofs must have at least one peak
        acc.unwrap_or_else(|| Hash::from([0u8; 32]))
    }
}

/// MMR accumulator with delta support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrAccumulator {
    /// All nodes in the MMR
    nodes: HashMap<u64, MmrNode>,
    /// Current peaks of all mountains
    peaks: Vec<u64>,
    /// Heights for current peaks (same length as peaks)
    peak_heights: Vec<u32>,
    /// Current size of the MMR
    size: u64,
}

impl Default for MmrAccumulator {
    fn default() -> Self { Self::new() }
}

impl MmrAccumulator {
    /// Provide a default empty accumulator
    pub fn default_impl() -> Self {
        Self::new()
    }
    /// Create a new empty MMR accumulator
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            peaks: Vec::new(),
            peak_heights: Vec::new(),
            size: 0,
        }
    }

    /// Get the current size of the MMR
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get all current peak positions
    pub fn peaks(&self) -> &[u64] {
        &self.peaks
    }

    /// Get a node by position
    pub fn get_node(&self, position: u64) -> Option<&MmrNode> {
        self.nodes.get(&position)
    }

    /// Append a new element to the MMR
    pub fn append(&mut self, hash: Hash) -> Result<u64> {
        let position = self.size;
        let node = MmrNode::new(hash, position);

        // Add the new node
        self.nodes.insert(position, node);

        // Account for the leaf node position
        self.size += 1;

        // Update peaks by pushing the new leaf and merging mountains of equal height repeatedly
        let mut curr_pos = position;
        let mut curr_h: u32 = 0;
        while let Some(&last_h) = self.peak_heights.last() {
            if last_h != curr_h {
                break;
            }
            let left_peak = match self.peaks.pop() {
                Some(p) => p,
                None => break,
            };
            self.peak_heights.pop();
            let merged_position = self.size;
            let merged_hash = self.merge_nodes(left_peak, curr_pos)?;
            self.nodes
                .insert(merged_position, MmrNode::new(merged_hash, merged_position));
            self.size += 1;
            curr_pos = merged_position;
            curr_h += 1;
        }
        self.peaks.push(curr_pos);
        self.peak_heights.push(curr_h);

        Ok(position)
    }

    /// Merge two nodes to create a parent node
    fn merge_nodes(&self, left_pos: u64, right_pos: u64) -> Result<Hash> {
        let left_node = self
            .nodes
            .get(&left_pos)
            .ok_or_else(|| anyhow!("Left node not found"))?;
        let right_node = self
            .nodes
            .get(&right_pos)
            .ok_or_else(|| anyhow!("Right node not found"))?;

        // Domain-separated parent hashing for MMR inner nodes
        Ok(mmr_hash_parent(&left_node.hash.0, &right_node.hash.0))
    }

    /// Get the root hash of the MMR
    pub fn root(&self) -> Option<Hash> {
        if self.peaks.is_empty() {
            None
        } else {
            let mut acc: Option<Hash> = None;
            for &peak_pos in self.peaks.iter().rev() {
                let peak_hash = match self.nodes.get(&peak_pos) {
                    Some(n) => n.hash.0,
                    None => return None,
                };
                acc = Some(match acc {
                    None => peak_hash,
                    Some(r) => mmr_hash_parent(&peak_hash, &r),
                });
            }
            acc
        }
    }

    /// Generate a proof for the element at the given position
    pub fn prove(&self, position: u64) -> Result<MmrProof> {
        if position >= self.size {
            return Err(anyhow!("Position out of bounds").into());
        }
        let element = match self.nodes.get(&position) {
            Some(n) => *n,
            None => return Err(anyhow!("Element not found").into()),
        };

        // Generate siblings bottom-up until reaching a peak (i.e., no parent present)
        let mut siblings = Vec::new();
        let mut current_pos = position;
        loop {
            let sib_pos = mmr_sibling_pos(current_pos);
            if let Some(sibling) = self.nodes.get(&sib_pos) {
                siblings.push(*sibling);
            } else {
                break;
            }
            let parent_pos = mmr_parent_pos(current_pos);
            if self.nodes.contains_key(&parent_pos) {
                current_pos = parent_pos;
            } else {
                break;
            }
        }

        Ok(MmrProof {
            element,
            siblings,
            peaks: {
                let mut out = Vec::with_capacity(self.peaks.len());
                for &pos in &self.peaks {
                    if let Some(n) = self.nodes.get(&pos) {
                        out.push(*n);
                    } else {
                        return Err(anyhow!("Peak node missing").into());
                    }
                }
                out
            },
        })
    }

    /// Apply a batch of deltas to the MMR
    pub fn apply_deltas(&mut self, deltas: &[MmrDelta]) -> Result<()> {
        for delta in deltas {
            match delta {
                MmrDelta::Append { hash } => {
                    self.append(hash.0)?;
                }
                MmrDelta::BatchAppend { hashes } => {
                    for hash in hashes {
                        self.append(hash.0)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Get all nodes in a specific range for witness updates
    pub fn get_witness_range(&self, start: u64, end: u64) -> Vec<MmrNode> {
        if start >= end {
            return Vec::new();
        }
        let capped_end = end.min(self.size);
        (start..capped_end)
            .filter_map(|pos| self.nodes.get(&pos).copied())
            .collect()
    }
}

/// Tachygram accumulator: a thin wrapper over the MMR providing
/// batch insertions and membership proofs for 32-byte elements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TachygramAccumulator {
    /// Underlying MMR accumulator
    mmr: MmrAccumulator,
    /// Map from element bytes to MMR positions for membership proving
    index: HashMap<[u8; 32], Vec<u64>>, // an element may appear multiple times
}

impl Default for TachygramAccumulator {
    fn default() -> Self { Self::new() }
}

impl TachygramAccumulator {
    /// Create a new empty Tachygram accumulator
    pub fn new() -> Self {
        Self {
            mmr: MmrAccumulator::new(),
            index: HashMap::new(),
        }
    }

    /// Current size (MMR positions, including inner nodes)
    pub fn size(&self) -> u64 {
        self.mmr.size()
    }

    /// Compute leaf hash for an element under tachygram domain separation
    fn leaf_hash(element: &[u8; 32]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tachygram:leaf:v1");
        hasher.update(element);
        hasher.finalize()
    }

    /// Insert a single element and return its leaf position in the MMR
    pub fn insert(&mut self, element: [u8; 32]) -> Result<u64> {
        let h = Self::leaf_hash(&element);
        let pos = self.mmr.append(h)?;
        self.index.entry(element).or_default().push(pos);
        Ok(pos)
    }

    /// Batch-insert elements
    pub fn batch_insert(&mut self, elements: &[[u8; 32]]) -> Result<()> {
        for e in elements {
            let _ = self.insert(*e)?;
        }
        Ok(())
    }

    /// Get current root of the accumulator (None if empty)
    pub fn root(&self) -> Option<[u8; 32]> {
        self.mmr.root().map(|h| *h.as_bytes())
    }

    /// Produce a membership proof for the given element, if present.
    pub fn prove(&self, element: &[u8; 32]) -> Result<TachygramMembershipProof> {
        let Some(positions) = self.index.get(element) else {
            return Err(anyhow!("Element not found").into());
        };
        let &pos = positions
            .first()
            .ok_or_else(|| anyhow!("Element positions missing"))?;
        let proof = self.mmr.prove(pos)?;
        Ok(TachygramMembershipProof {
            element: *element,
            proof,
        })
    }
}

/// Membership proof carrying the original element and the underlying MMR proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TachygramMembershipProof {
    /// Original 32-byte element
    pub element: [u8; 32],
    /// Underlying MMR proof
    pub proof: MmrProof,
}

impl TachygramMembershipProof {
    /// Verify this membership proof against an expected root.
    /// Ensures the leaf hash corresponds to the element, and the path validates to the root.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let leaf = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"tachygram:leaf:v1");
            hasher.update(&self.element);
            hasher.finalize()
        };

        if self.proof.element.hash.0 != leaf {
            return false;
        }

        let root = Hash::from(*expected_root);
        self.proof.verify(&root)
    }
}

/// Delta operations for efficient MMR updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MmrDelta {
    /// Append a single element
    Append { hash: SerializableHash },
    /// Append multiple elements at once
    BatchAppend { hashes: Vec<SerializableHash> },
}

/// Witness for efficient MMR membership proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrWitness {
    /// Position of the element in the MMR
    pub position: u64,
    /// Authentication path nodes
    pub auth_path: Vec<(u64, SerializableHash)>,
    /// Current peaks
    pub peaks: Vec<(u64, SerializableHash)>,
}

impl MmrWitness {
    /// Update the witness for a new MMR state
    pub fn update(&mut self, new_peaks: &[(u64, Hash)]) {
        self.peaks = new_peaks
            .iter()
            .map(|(pos, hash)| (*pos, SerializableHash(*hash)))
            .collect();
    }

    /// Verify that an element is in the MMR using this witness
    pub fn verify(&self, element_hash: &Hash, mmr_root: &Hash) -> bool {
        // Recompute the mountain peak by walking the authentication path bottom-up.
        let mut current_hash = *element_hash;
        let mut current_pos = self.position;

        for (sib_pos, sib_hash) in &self.auth_path {
            let (left, right) = if *sib_pos < current_pos {
                (sib_hash.0, current_hash)
            } else {
                (current_hash, sib_hash.0)
            };
            current_hash = mmr_hash_parent(&left, &right);
            current_pos = mmr_parent_pos(current_pos);
        }

        // Bag peaks from right to left, substituting the computed mountain peak
        let mut acc: Option<Hash> = None;
        for (peak_pos, peak_hash) in self.peaks.iter().rev() {
            let peak_h = if *peak_pos == current_pos {
                current_hash
            } else {
                peak_hash.0
            };
            acc = Some(match acc {
                None => peak_h,
                Some(r) => mmr_hash_parent(&peak_h, &r),
            });
        }

        match acc {
            Some(root) => root == *mmr_root,
            None => return false, // Empty witness cannot be valid
        }
    }

    /// Apply a witness update produced against a new MMR state.
    pub fn apply_update(&mut self, update: &MmrWitnessUpdate) {
        if !update.auth_path_updates.is_empty() {
            self.auth_path = update.auth_path_updates.clone();
        }
        if !update.new_peaks.is_empty() {
            self.peaks = update
                .new_peaks
                .iter()
                .map(|(pos, h)| (*pos, *h))
                .collect();
        }
    }
}

/// Persistence layer
pub trait MmrStorage {
    fn clear(&mut self);
    fn put_meta(&mut self, meta: &MmrMeta);
    fn get_meta(&self) -> Option<MmrMeta>;
    fn put_node(&mut self, node: MmrNode);
    fn get_node(&self, position: u64) -> Option<MmrNode>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrMeta {
    pub size: u64,
    pub peaks: Vec<u64>,
    pub peak_heights: Vec<u32>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InMemoryMmrStorage {
    nodes: HashMap<u64, MmrNode>,
    meta: Option<MmrMeta>,
}

impl MmrStorage for InMemoryMmrStorage {
    fn clear(&mut self) {
        self.nodes.clear();
        self.meta = None;
    }
    fn put_meta(&mut self, meta: &MmrMeta) {
        self.meta = Some(meta.clone());
    }
    fn get_meta(&self) -> Option<MmrMeta> {
        self.meta.clone()
    }
    fn put_node(&mut self, node: MmrNode) {
        self.nodes.insert(node.position, node);
    }
    fn get_node(&self, position: u64) -> Option<MmrNode> {
        self.nodes.get(&position).copied()
    }
}

impl MmrAccumulator {
    /// Persist full state (meta + nodes) to a storage backend
    pub fn persist_to<S: MmrStorage>(&self, storage: &mut S) {
        storage.clear();
        storage.put_meta(&MmrMeta {
            size: self.size,
            peaks: self.peaks.clone(),
            peak_heights: self.peak_heights.clone(),
        });
        for node in self.nodes.values() {
            storage.put_node(*node);
        }
    }

    /// Load full state from a storage backend
    pub fn load_from<S: MmrStorage>(storage: &S) -> Result<Self> {
        let meta = storage
            .get_meta()
            .ok_or_else(|| anyhow!("No MMR metadata in storage"))?;
        let mut nodes = HashMap::new();
        for pos in 0..meta.size {
            if let Some(n) = storage.get_node(pos) {
                nodes.insert(pos, n);
            }
        }
        Ok(Self {
            nodes,
            peaks: meta.peaks,
            peak_heights: meta.peak_heights,
            size: meta.size,
        })
    }

    /// Compute a targeted witness update for the element at `position` against this MMR state.
    /// Returns only the updated auth path and current peaks, avoiding full witness recomputation for others.
    pub fn compute_witness_update(&self, position: u64) -> Result<MmrWitnessUpdate> {
        if position >= self.size {
            return Err(anyhow!("Position out of bounds").into());
        }
        // Rebuild the auth path for this position by walking siblings upward until reaching a peak.
        let mut auth_path: Vec<(u64, SerializableHash)> = Vec::new();
        let mut current_pos = position;
        loop {
            let sib_pos = mmr_sibling_pos(current_pos);
            if let Some(sibling) = self.nodes.get(&sib_pos) {
                auth_path.push((sibling.position, sibling.hash));
            } else {
                break;
            }
            let parent_pos = mmr_parent_pos(current_pos);
            if self.nodes.contains_key(&parent_pos) {
                current_pos = parent_pos;
            } else {
                break;
            }
        }

        // Snapshot current peaks
        let mut peaks: Vec<(u64, SerializableHash)> = Vec::with_capacity(self.peaks.len());
        for &pos in &self.peaks {
            let Some(n) = self.nodes.get(&pos) else { return Err(anyhow!("Peak node missing").into()); };
            peaks.push((n.position, n.hash));
        }

        Ok(MmrWitnessUpdate { auth_path_updates: auth_path, new_peaks: peaks })
    }
}

/// Compact witness update describing only the parts that changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrWitnessUpdate {
    /// Replacement authentication path nodes (position, hash)
    pub auth_path_updates: Vec<(u64, SerializableHash)>,
    /// New current peaks for the accumulator
    pub new_peaks: Vec<(u64, SerializableHash)>,
}

/// Tests for the MMR accumulator
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_creation() {
        let mmr = MmrAccumulator::new();
        assert_eq!(mmr.size(), 0);
        assert_eq!(mmr.peaks().len(), 0);
        assert_eq!(mmr.root(), None);
    }

    #[test]
    fn test_mmr_append() {
        let mut mmr = MmrAccumulator::new();

        let hash1 = Hash::from([1u8; 32]);
        let hash2 = Hash::from([2u8; 32]);
        let hash3 = Hash::from([3u8; 32]);

        let pos1 = mmr.append(hash1).unwrap();
        assert_eq!(pos1, 0);
        assert_eq!(mmr.size(), 1);

        let pos2 = mmr.append(hash2).unwrap();
        assert_eq!(pos2, 1);
        assert_eq!(mmr.size(), 3); // includes parent at position 2

        let pos3 = mmr.append(hash3).unwrap();
        assert_eq!(pos3, 3);
        assert_eq!(mmr.size(), 4);
    }

    #[test]
    fn test_mmr_proof() {
        let mut mmr = MmrAccumulator::new();

        let hash1 = Hash::from([1u8; 32]);
        let pos1 = mmr.append(hash1).unwrap();

        let proof = mmr.prove(pos1).unwrap();
        assert_eq!(proof.element.position, pos1);
        assert_eq!(proof.element.hash.0, hash1);
    }

    #[test]
    fn test_mmr_deltas() {
        let mut mmr = MmrAccumulator::new();

        let hash1 = Hash::from([1u8; 32]);
        let hash2 = Hash::from([2u8; 32]);

        let deltas = vec![
            MmrDelta::Append {
                hash: SerializableHash(hash1),
            },
            MmrDelta::Append {
                hash: SerializableHash(hash2),
            },
        ];

        mmr.apply_deltas(&deltas).unwrap();
        assert_eq!(mmr.size(), 3);
    }

    #[test]
    fn test_mmr_batch_deltas() {
        let mut mmr = MmrAccumulator::new();

        let hashes = vec![
            SerializableHash(Hash::from([1u8; 32])),
            SerializableHash(Hash::from([2u8; 32])),
            SerializableHash(Hash::from([3u8; 32])),
        ];

        let deltas = vec![MmrDelta::BatchAppend { hashes }];

        mmr.apply_deltas(&deltas).unwrap();
        assert_eq!(mmr.size(), 4);
    }

    #[test]
    fn test_node_properties() {
        let hash = Hash::from([0u8; 32]);
        let node = MmrNode::new(hash, 0);

        assert_eq!(node.position, 0);
        assert_eq!(node.height(), 0);
        assert!(node.is_peak());
    }

    #[test]
    fn test_witness_range() {
        let mut mmr = MmrAccumulator::new();

        let hash1 = Hash::from([1u8; 32]);
        let hash2 = Hash::from([2u8; 32]);
        let hash3 = Hash::from([3u8; 32]);

        mmr.append(hash1).unwrap();
        mmr.append(hash2).unwrap();
        mmr.append(hash3).unwrap();

        let witness_nodes = mmr.get_witness_range(0, 2);
        assert_eq!(witness_nodes.len(), 2);
    }

    #[test]
    fn test_mmr_proof_verify_and_root() {
        let mut mmr = MmrAccumulator::new();
        let h1 = Hash::from([1u8; 32]);
        let h2 = Hash::from([2u8; 32]);
        let h3 = Hash::from([3u8; 32]);
        let p1 = mmr.append(h1).unwrap();
        let _p2 = mmr.append(h2).unwrap();
        let _p3 = mmr.append(h3).unwrap();
        let root = mmr.root().unwrap();

        let proof1 = mmr.prove(p1).unwrap();
        assert!(proof1.verify(&root));
        assert_eq!(proof1.calculate_root(), root);
    }

    #[test]
    fn test_mmr_witness_verify_matches_proof() {
        // Build a small MMR and produce a proof for a leaf
        let mut mmr = MmrAccumulator::new();
        let h1 = Hash::from([1u8; 32]);
        let h2 = Hash::from([2u8; 32]);
        let h3 = Hash::from([3u8; 32]);
        let p1 = mmr.append(h1).unwrap();
        let _p2 = mmr.append(h2).unwrap();
        let _p3 = mmr.append(h3).unwrap();
        let root = mmr.root().unwrap();

        let proof = mmr.prove(p1).unwrap();

        // Convert MmrProof into a MmrWitness view
        let mut witness = MmrWitness {
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

        // Update peaks no-op (ensures method compiles and preserves data)
        let new_peaks: Vec<(u64, Hash)> = witness
            .peaks
            .iter()
            .map(|(pos, h)| (*pos, h.0))
            .collect();
        witness.update(&new_peaks);

        assert!(witness.verify(&h1, &root));
    }

    #[test]
    fn test_mmr_persistence_roundtrip() {
        let mut mmr = MmrAccumulator::new();
        let h1 = Hash::from([10u8; 32]);
        let h2 = Hash::from([11u8; 32]);
        let _ = mmr.append(h1).unwrap();
        let _ = mmr.append(h2).unwrap();
        let root_before = mmr.root().unwrap();

        let mut storage = InMemoryMmrStorage::default();
        mmr.persist_to(&mut storage);
        let loaded = MmrAccumulator::load_from(&storage).unwrap();
        assert_eq!(loaded.size(), mmr.size());
        assert_eq!(loaded.peaks(), mmr.peaks());
        assert_eq!(loaded.root().unwrap(), root_before);
    }

    #[test]
    fn test_tachygram_insert_and_prove() {
        let mut tg = TachygramAccumulator::new();
        let e1 = [1u8; 32];
        let e2 = [2u8; 32];
        tg.batch_insert(&[e1, e2]).unwrap();
        let root = tg.root().unwrap();
        let proof = tg.prove(&e1).unwrap();
        assert!(proof.verify(&root));
    }
}
