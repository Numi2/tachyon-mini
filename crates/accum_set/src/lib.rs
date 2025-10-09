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

/// Compact membership witness (placeholder)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipWitness {
    /// Element proved
    pub element: [u8; 32],
    /// Accumulator root at time of witness creation
    pub root: [u8; 32],
}

impl MembershipWitness {
    /// Verify witness against a root (placeholder)
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        &self.root == expected_root
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

    /// Create a membership witness (placeholder)
    pub fn create_membership_witness(&self, element: &[u8; 32]) -> Result<MembershipWitness> {
        if !self.contains(element) {
            return Err(anyhow!("Element not in set"));
        }
        Ok(MembershipWitness {
            element: *element,
            root: self.root,
        })
    }

    fn recompute_root(&mut self) {
        // Compute root by hashing concatenated element hashes in sorted order (placeholder)
        let mut acc = blake3::Hasher::new();
        acc.update(b"accum_set:root:v1");
        for e in &self.elements {
            let h = hash_element(e);
            acc.update(h.as_bytes());
        }
        self.root.copy_from_slice(acc.finalize().as_bytes());
    }
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


