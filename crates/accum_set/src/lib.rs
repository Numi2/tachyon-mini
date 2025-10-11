//! # accum_set
//!
//! Sparse accumulator for nullifiers and note commitments supporting batch (non-)membership checks.
//! This is a simplified stand-in for a cryptographic accumulator suitable for PCD integration.

use anyhow::{anyhow, Result};
use blake3::Hash;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
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



// ===== 16-ary Sparse Merkle Tree (SMT-16) for nullifiers =====

use std::collections::HashMap;

/// Depth for 256-bit keys using 4-bit nibbles
pub const SMT16_DEPTH: usize = 64;
/// Node arity
pub const SMT16_ARITY: usize = 16;

#[inline]
fn smt16_hash_leaf(key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"smt16:leaf:v1");
    h.update(key);
    *h.finalize().as_bytes()
}

#[inline]
fn smt16_hash_node(level: usize, children: &[[u8; 32]; SMT16_ARITY]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"smt16:node:v1");
    h.update(&(level as u32).to_le_bytes());
    for c in children {
        h.update(c);
    }
    *h.finalize().as_bytes()
}

#[inline]
fn smt16_empty_hashes() -> Vec<[u8; 32]> {
    // EMPTY[DEPTH] = hash of empty leaf; EMPTY[l] = hash of node of EMPTY[l+1] children
    let mut empty = vec![[0u8; 32]; SMT16_DEPTH + 1];
    empty[SMT16_DEPTH] = {
        let mut h = blake3::Hasher::new();
        h.update(b"smt16:leaf:empty:v1");
        *h.finalize().as_bytes()
    };
    for l in (0..SMT16_DEPTH).rev() {
        let mut kids = [[0u8; 32]; SMT16_ARITY];
        for slot in kids.iter_mut().take(SMT16_ARITY) { *slot = empty[l + 1]; }
        empty[l] = smt16_hash_node(l, &kids);
    }
    empty
}

#[inline]
fn smt16_key_to_nibbles(key: &[u8; 32]) -> [u8; SMT16_DEPTH] {
    let mut out = [0u8; SMT16_DEPTH];
    let mut idx = 0usize;
    for b in key {
        out[idx] = b >> 4;
        out[idx + 1] = b & 0x0f;
        idx += 2;
    }
    out
}

#[inline]
fn smt16_make_node_idx(level: usize, path_prefix: &[u8]) -> u64 {
    // Compact key: upper 8 bits = level, lower 56 bits = first 7 bytes of blake3(path)
    let mut h = blake3::Hasher::new();
    h.update(b"smt16:nk:v1");
    h.update(&[level as u8]);
    h.update(path_prefix);
    let bytes = h.finalize();
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&bytes.as_bytes()[..8]);
    let mut v = u64::from_le_bytes(lo);
    v &= 0x00FF_FFFF_FFFF_FFFFu64;
    v | ((level as u64) << 56)
}

/// Insert-only delta operations for SMT-16
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Smt16Delta {
    Insert { key: [u8; 32] },
    BatchInsert { keys: Vec<[u8; 32]> },
}

/// Non-membership proof for SMT-16
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smt16NonMembershipProof {
    /// Nibble per level (64 entries)
    #[serde(with = "BigArray")]
    pub path: [u8; SMT16_DEPTH],
    /// For each level l, the 15 siblings for children except index path[l]
    pub siblings: Vec<[[u8; 32]; SMT16_ARITY - 1]>,
}

impl Smt16NonMembershipProof {
    pub fn verify_for_key(&self, key: &[u8; 32], expected_root: &[u8; 32]) -> bool {
        let empty = smt16_empty_hashes();
        if self.siblings.len() != SMT16_DEPTH { return false; }
        let kpath = smt16_key_to_nibbles(key);
        if self.path != kpath { return false; }

        // Start from empty leaf
        let mut cur = empty[SMT16_DEPTH];
        for level in (0..SMT16_DEPTH).rev() {
            let idx = self.path[level] as usize;
            let sibs = &self.siblings[level];
            let mut children = [[0u8; 32]; SMT16_ARITY];
            let mut s_i = 0usize;
            for (j, child) in children.iter_mut().enumerate().take(SMT16_ARITY) {
                if j == idx { *child = cur; } else { *child = sibs[s_i]; s_i += 1; }
            }
            cur = smt16_hash_node(level, &children);
        }
        &cur == expected_root
    }
}

/// 16-ary Sparse Merkle Tree accumulator (insert-only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Smt16Accumulator {
    /// Present keys
    elements: BTreeSet<[u8; 32]>,
    /// Partial node cache: (level,path_prefix) -> hash
    nodes: HashMap<u64, [u8; 32]>,
    /// Cached root
    root: [u8; 32],
}

impl Default for Smt16Accumulator { fn default() -> Self { Self::new() } }

impl Smt16Accumulator {
    pub fn new() -> Self {
        let empty = smt16_empty_hashes();
        Self { elements: BTreeSet::new(), nodes: HashMap::new(), root: empty[0] }
    }

    pub fn root(&self) -> [u8; 32] { self.root }
    pub fn len(&self) -> usize { self.elements.len() }
    pub fn is_empty(&self) -> bool { self.elements.is_empty() }
    pub fn contains(&self, key: &[u8; 32]) -> bool { self.elements.contains(key) }

    pub fn insert(&mut self, key: [u8; 32]) {
        if self.elements.contains(&key) { return; }
        self.elements.insert(key);
        self.update_path_after_insert(&key);
    }

    pub fn apply_delta(&mut self, delta: Smt16Delta) -> Result<()> {
        match delta {
            Smt16Delta::Insert { key } => self.insert(key),
            Smt16Delta::BatchInsert { keys } => {
                for k in keys { self.insert(k); }
            }
        }
        Ok(())
    }

    pub fn create_non_membership_witness(&self, key: &[u8; 32]) -> Result<Smt16NonMembershipProof> {
        if self.contains(key) { return Err(anyhow!("Key present; cannot create non-membership proof")); }
        let empty = smt16_empty_hashes();
        let path = smt16_key_to_nibbles(key);
        let mut siblings: Vec<[[u8; 32]; SMT16_ARITY - 1]> = vec![[[0u8; 32]; SMT16_ARITY - 1]; SMT16_DEPTH];
        let mut prefix: Vec<u8> = Vec::new();
        for level in 0..SMT16_DEPTH {
            let idx = path[level] as usize;
            let mut sibs = [[0u8; 32]; SMT16_ARITY - 1];
            let mut s_i = 0usize;
            for j in 0..SMT16_ARITY {
                if j == idx { continue; }
                let mut child_prefix = prefix.clone();
                child_prefix.push(j as u8);
                let nk = smt16_make_node_idx(level + 1, &child_prefix);
                let h = self.nodes.get(&nk).copied().unwrap_or(empty[level + 1]);
                sibs[s_i] = h;
                s_i += 1;
            }
            siblings[level] = sibs;
            prefix.push(path[level]);
        }
        Ok(Smt16NonMembershipProof { path, siblings })
    }

    fn update_path_after_insert(&mut self, key: &[u8; 32]) {
        let empty = smt16_empty_hashes();
        let path = smt16_key_to_nibbles(key);

        // Set leaf
        let mut cur = smt16_hash_leaf(key);
        let mut prefix: Vec<u8> = path.to_vec();
        let leaf_idx = smt16_make_node_idx(SMT16_DEPTH, &prefix);
        self.nodes.insert(leaf_idx, cur);

        // Bubble up
        for level in (0..SMT16_DEPTH).rev() {
            prefix.truncate(level);
            let idx = path[level] as usize;
            let mut children = [[0u8; 32]; SMT16_ARITY];
            for (j, child) in children.iter_mut().enumerate().take(SMT16_ARITY) {
                let mut child_prefix = prefix.clone();
                child_prefix.push(j as u8);
                if j == idx {
                    *child = cur;
                } else {
                    let nk = smt16_make_node_idx(level + 1, &child_prefix);
                    *child = self.nodes.get(&nk).copied().unwrap_or(empty[level + 1]);
                }
            }
            let parent_hash = smt16_hash_node(level, &children);
            let parent_idx = smt16_make_node_idx(level, &prefix);
            self.nodes.insert(parent_idx, parent_hash);
            cur = parent_hash;
        }
        self.root = cur;
    }
}

#[cfg(test)]
mod smt16_tests {
    use super::*;

    #[test]
    fn test_smt16_empty_root() {
        let a = Smt16Accumulator::new();
        let b = Smt16Accumulator::new();
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn test_smt16_insert_and_non_membership() {
        let mut acc = Smt16Accumulator::new();
        let nf_present = [1u8; 32];
        let nf_absent = [2u8; 32];
        acc.insert(nf_present);
        assert!(acc.contains(&nf_present));
        assert!(!acc.contains(&nf_absent));
        let proof = acc.create_non_membership_witness(&nf_absent).unwrap();
        assert!(proof.verify_for_key(&nf_absent, &acc.root()));
        assert!(!proof.verify_for_key(&nf_present, &acc.root()));
    }
}
