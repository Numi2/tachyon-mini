//! # accum_set
//!
//! Sparse accumulator for nullifiers and note commitments supporting batch (non-)membership checks.
//! This is a simplified stand-in for a cryptographic accumulator suitable for PCD integration.

use anyhow::{anyhow, Result};
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A domain-separated hash for set elements
fn hash_element(elem: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"accum_set:v1");
    hasher.update(elem);
    hasher.finalize()
}

/// Accumulator delta operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SetDelta {
    /// Insert one element
    Insert { element: [u8; 32] },
    /// Remove one element
    Remove { element: [u8; 32] },
    /// Batch insert
    BatchInsert { elements: Vec<[u8; 32]> },
    /// Batch remove
    BatchRemove { elements: Vec<[u8; 32]> },
}

/// Merkle membership witness over sorted set elements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipWitness {
    /// Element proved
    pub element: [u8; 32],
    /// Blake3 hash of the element (leaf)
    pub leaf_hash: [u8; 32],
    /// Index of the leaf in the sorted set (by element bytes)
    pub leaf_index: usize,
    /// Authentication path of sibling hashes bottom-up
    pub auth_path: Vec<[u8; 32]>,
}

impl MembershipWitness {
    /// Verify witness against a Merkle root computed with duplicating lone nodes
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let mut idx = self.leaf_index;
        let mut acc = self.leaf_hash;
        for sib in &self.auth_path {
            acc = if idx % 2 == 0 {
                hash_nodes(&acc, sib)
            } else {
                hash_nodes(sib, &acc)
            };
            idx /= 2;
        }
        &acc == expected_root
    }
}

/// Sparse set accumulator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAccumulator {
    /// Elements (as 32-byte representatives)
    elements: BTreeSet<[u8; 32]>,
    /// Cached root hash
    root: [u8; 32],
}

impl Default for SetAccumulator {
    fn default() -> Self { Self::new() }
}

impl SetAccumulator {
    /// Create a new empty accumulator
    pub fn new() -> Self {
        Self {
            elements: BTreeSet::new(),
            root: [0u8; 32],
        }
    }

    /// Current root commitment
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of elements
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Whether empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Check membership
    pub fn contains(&self, element: &[u8; 32]) -> bool {
        self.elements.contains(element)
    }

    /// Insert element
    pub fn insert(&mut self, element: [u8; 32]) {
        self.elements.insert(element);
        self.recompute_root();
    }

    /// Remove element
    pub fn remove(&mut self, element: &[u8; 32]) {
        self.elements.remove(element);
        self.recompute_root();
    }

    /// Apply a delta
    pub fn apply_delta(&mut self, delta: SetDelta) -> Result<()> {
        match delta {
            SetDelta::Insert { element } => self.elements.insert(element),
            SetDelta::Remove { element } => self.elements.remove(&element),
            SetDelta::BatchInsert { elements } => {
                for e in elements {
                    self.elements.insert(e);
                }
                true
            }
            SetDelta::BatchRemove { elements } => {
                let mut any = false;
                for e in elements {
                    any |= self.elements.remove(&e);
                }
                any
            }
        };
        self.recompute_root();
        Ok(())
    }

    /// Create a membership witness for an element
    pub fn create_membership_witness(&self, element: &[u8; 32]) -> Result<MembershipWitness> {
        if !self.contains(element) {
            return Err(anyhow!("Element not in set"));
        }

        // Build sorted leaf list and locate index
        let elements_vec: Vec<[u8; 32]> = self.elements.iter().cloned().collect();
        let leaf_index = elements_vec
            .iter()
            .position(|e| e == element)
            .ok_or_else(|| anyhow!("Element not in set (inconsistent)"))?;

        let leaves: Vec<[u8; 32]> = elements_vec
            .iter()
            .map(|e| {
                let h = hash_element(e);
                let mut out = [0u8; 32];
                out.copy_from_slice(h.as_bytes());
                out
            })
            .collect();

        let auth_path = build_merkle_path(&leaves, leaf_index);

        let leaf_hash = {
            let h = hash_element(element);
            let mut out = [0u8; 32];
            out.copy_from_slice(h.as_bytes());
            out
        };

        Ok(MembershipWitness {
            element: *element,
            leaf_hash,
            leaf_index,
            auth_path,
        })
    }

    fn recompute_root(&mut self) {
        // Compute Merkle root over hashed leaves in sorted order
        let leaves: Vec<[u8; 32]> = self
            .elements
            .iter()
            .map(|e| {
                let h = hash_element(e);
                let mut out = [0u8; 32];
                out.copy_from_slice(h.as_bytes());
                out
            })
            .collect();
        self.root = compute_merkle_root(&leaves);
    }
}

/// Hash two 32-byte nodes into a parent using domain separation
fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"accum_set:node:v1");
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Compute a Merkle root over the provided leaves. If odd, duplicate last.
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            next.push(hash_nodes(&left, &right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Build a Merkle authentication path for the leaf at index
fn build_merkle_path(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    if leaves.is_empty() {
        return path;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let is_right = index % 2 == 1;
        let sibling_index = if is_right { index - 1 } else { index + 1 };
        let sibling = if sibling_index < level.len() {
            level[sibling_index]
        } else {
            // Duplicate if no sibling
            level[index]
        };
        path.push(sibling);

        // Build next level
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            next.push(hash_nodes(&left, &right));
            i += 2;
        }
        level = next;
        index /= 2;
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_accumulator() {
        let mut acc = SetAccumulator::new();
        assert_eq!(acc.root(), [0u8; 32]);
        let e1 = [1u8; 32];
        let e2 = [2u8; 32];
        acc.insert(e1);
        let r1 = acc.root();
        assert_ne!(r1, [0u8; 32]);
        acc.insert(e2);
        let r2 = acc.root();
        assert_ne!(r2, r1);
        assert!(acc.contains(&e1));
        let wit = acc.create_membership_witness(&e1).unwrap();
        assert!(wit.verify(&acc.root()));
        acc.remove(&e1);
        assert!(!acc.contains(&e1));
        assert_ne!(acc.root(), r2);
    }
}


