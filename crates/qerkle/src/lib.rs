//! qerkle: Dynamic-hash Merkle tree with optional Kyber-encrypted metadata
//! Numan Thabit 2025
//! Provides:
//! - Dynamic hashing over BLAKE3 and Poseidon (same Poseidon spec as `circuits`)
//! - Simple inclusion proof generation/verification with per-edge hash choice bits
//! - Helpers to encrypt metadata (root + hash indices) using pq_crypto Kyber/AES-GCM

use anyhow::{anyhow, Result};
use blake3::Hasher as Blake3Hasher;
use ff::{PrimeField, FromUniformBytes};
use halo2_gadgets::poseidon::primitives::{self as poseidon_primitives, ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;
use pq_crypto::{KyberPublicKey, KyberSecretKey, SimpleAead, SimpleKem, AES_NONCE_SIZE};
use serde::{Deserialize, Serialize};

/// 32-byte hash output size
pub const HASH_SIZE: usize = 32;

/// Hash function choice used at each edge of the tree
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashChoice {
    Blake3,
    Poseidon,
}

impl HashChoice {
    pub fn all() -> [HashChoice; 2] { [HashChoice::Blake3, HashChoice::Poseidon] }
}


/// Hash two 32-byte nodes into a parent according to choice
fn hash_pair(choice: HashChoice, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    match choice {
        HashChoice::Blake3 => {
            let mut h = Blake3Hasher::new();
            h.update(left);
            h.update(right);
            *h.finalize().as_bytes()
        }
        HashChoice::Poseidon => {
            // Map each 32-byte node into field via uniform bytes using XOF
            use std::io::Read as _;
            let mut h_l = Blake3Hasher::new();
            h_l.update(b"qerkle:fr:left:v1");
            h_l.update(left);
            let mut xof_l = h_l.finalize_xof();
            let mut wide_l = [0u8; 64];
            xof_l.read_exact(&mut wide_l).unwrap();
            let lf = Fr::from_uniform_bytes(&wide_l);

            let mut h_r = Blake3Hasher::new();
            h_r.update(b"qerkle:fr:right:v1");
            h_r.update(right);
            let mut xof_r = h_r.finalize_xof();
            let mut wide_r = [0u8; 64];
            xof_r.read_exact(&mut wide_r).unwrap();
            let rf = Fr::from_uniform_bytes(&wide_r);
            let digest = poseidon_primitives::Hash::<Fr, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([lf, rf]);
            let mut out = [0u8; 32];
            out.copy_from_slice(digest.to_repr().as_ref());
            out
        }
    }
}

/// Deterministic pseudo-random choice from a seed and level index
fn choose_hash(seed: &[u8; 32], level: u32, position: u32) -> HashChoice {
    let mut h = Blake3Hasher::new();
    h.update(b"qerkle:choice:v1");
    h.update(seed);
    h.update(&level.to_le_bytes());
    h.update(&position.to_le_bytes());
    let b = h.finalize().as_bytes()[0] & 1;
    if b == 0 { HashChoice::Blake3 } else { HashChoice::Poseidon }
}

/// Inclusion proof for a leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Sibling nodes from leaf to root
    pub siblings: Vec<[u8; 32]>,
    /// For each level, whether current node was right child (true => node is right, sibling is left)
    pub is_right_child: Vec<bool>,
    /// Hash choices used at each level
    pub choices: Vec<HashChoice>,
    /// Seed used to select choices (to re-derive deterministically)
    pub seed: [u8; 32],
}

impl InclusionProof {
    pub fn verify(&self, leaf: &[u8; 32], root: &[u8; 32], index: u32) -> bool {
        if self.siblings.len() != self.is_right_child.len() || self.siblings.len() != self.choices.len() {
            return false;
        }
        let mut cur = *leaf;
        let mut idx = index;
        for (level, ((sib, right), choice)) in self
            .siblings
            .iter()
            .zip(self.is_right_child.iter())
            .zip(self.choices.iter())
            .enumerate()
        {
            let expected_choice = choose_hash(&self.seed, level as u32, idx);
            if *choice != expected_choice { return false; }
            cur = if *right {
                hash_pair(*choice, sib, &cur)
            } else {
                hash_pair(*choice, &cur, sib)
            };
            idx >>= 1;
        }
        &cur == root
    }
}

/// Qerkle builder: builds root and proofs using dynamic hashing
pub struct QerkleBuilder {
    pub seed: [u8; 32],
}

impl QerkleBuilder {
    pub fn new(seed: [u8; 32]) -> Self { Self { seed } }

    /// Build a qerkle root from leaves (32-byte commitment leaves). If odd, last is duplicated.
    pub fn build_root(&self, leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
        if leaves.is_empty() { return Err(anyhow!("no leaves")); }
        let mut level_nodes: Vec<[u8; 32]> = leaves.to_vec();
        let mut level: u32 = 0;
        while level_nodes.len() > 1 {
            let mut next = Vec::with_capacity(level_nodes.len().div_ceil(2));
            for i in (0..level_nodes.len()).step_by(2) {
                let left = level_nodes[i];
                let right = if i + 1 < level_nodes.len() { level_nodes[i + 1] } else { left };
                let choice = choose_hash(&self.seed, level, (i / 2) as u32);
                next.push(hash_pair(choice, &left, &right));
            }
            level_nodes = next;
            level += 1;
        }
        Ok(level_nodes[0])
    }

    /// Create an inclusion proof for leaf at `index`
    pub fn create_proof(&self, leaves: &[[u8; 32]], index: usize) -> Result<InclusionProof> {
        if leaves.is_empty() { return Err(anyhow!("no leaves")); }
        if index >= leaves.len() { return Err(anyhow!("index out of range")); }

        // Build all levels keeping siblings and choices
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];
        let mut choices_per_level: Vec<Vec<HashChoice>> = Vec::new();
        let mut level: u32 = 0;
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut level_choices: Vec<HashChoice> = Vec::with_capacity(next.capacity());
            for i in (0..cur.len()).step_by(2) {
                let left = cur[i];
                let right = if i + 1 < cur.len() { cur[i + 1] } else { left };
                let choice = choose_hash(&self.seed, level, (i / 2) as u32);
                level_choices.push(choice);
                next.push(hash_pair(choice, &left, &right));
            }
            choices_per_level.push(level_choices);
            levels.push(next);
            level += 1;
        }

        // Walk up the tree collecting siblings and orientation
        let mut siblings = Vec::new();
        let mut is_right_child = Vec::new();
        let mut choices = Vec::new();
        let mut idx = index;
        for (lvl_idx, nodes) in levels.iter().enumerate().take(levels.len() - 1) {
            let pair_start = idx - (idx % 2);
            let left = nodes[pair_start];
            let right = if pair_start + 1 < nodes.len() { nodes[pair_start + 1] } else { left };
            let right_child = idx % 2 == 1;
            let sibling = if right_child { left } else { right };
            siblings.push(sibling);
            is_right_child.push(right_child);
            choices.push(choices_per_level[lvl_idx][pair_start / 2]);
            idx /= 2;
        }

        Ok(InclusionProof { siblings, is_right_child, choices, seed: self.seed })
    }
}

/// Encrypted metadata bundle containing root and per-level choices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    /// Nonce used for AEAD
    pub nonce: [u8; AES_NONCE_SIZE],
    /// Ciphertext (nonce + ciphertext stored in pq_crypto style? We store nonce separately here)
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataPlaintext {
    pub root: [u8; 32],
    pub seed: [u8; 32],
}

impl EncryptedMetadata {
    pub fn encrypt(pk: &KyberPublicKey, root: [u8; 32], seed: [u8; 32]) -> Result<Self> {
        let (ct, shared) = SimpleKem::encapsulate(pk)?;
        let nonce = SimpleAead::generate_nonce();
        let pt = MetadataPlaintext { root, seed };
        let pt_bytes = bincode::serialize(&pt)?;
        let ciphertext = SimpleAead::encrypt(&shared, &nonce, &pt_bytes, b"qerkle:meta:v1")?;
        // Prepend KEM ct bytes so the receiver can decapsulate
        let mut out = Vec::new();
        out.extend_from_slice(ct.as_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(Self { nonce, ciphertext: out })
    }

    pub fn decrypt(&self, sk: &KyberSecretKey) -> Result<MetadataPlaintext> {
        // Split KEM ct and AEAD payload
        if self.ciphertext.len() < pq_crypto::KYBER_CIPHERTEXT_SIZE {
            return Err(anyhow!("ciphertext too short"));
        }
        let kem_ct_bytes = &self.ciphertext[..pq_crypto::KYBER_CIPHERTEXT_SIZE];
        let aead_bytes = &self.ciphertext[pq_crypto::KYBER_CIPHERTEXT_SIZE..];
        let kem_ct = pq_crypto::KyberCiphertext::from_bytes(kem_ct_bytes)?;
        let shared = pq_crypto::SimpleKem::decapsulate(sk, &kem_ct)?;
        let pt_bytes = SimpleAead::decrypt(&shared, aead_bytes, b"qerkle:meta:v1")?;
        let pt: MetadataPlaintext = bincode::deserialize(&pt_bytes)?;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_verify() {
        let seed = *blake3::hash(b"seed").as_bytes();
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| *blake3::hash(&[i as u8]).as_bytes()).collect();
        let builder = QerkleBuilder::new(seed);
        let root = builder.build_root(&leaves).unwrap();
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = builder.create_proof(&leaves, idx).unwrap();
            assert!(proof.verify(leaf, &root, idx as u32));
        }
    }

    #[test]
    fn test_encrypt_decrypt_metadata() {
        let (pk, sk) = pq_crypto::SimpleKem::generate_keypair().unwrap();
        let seed = *blake3::hash(b"seed").as_bytes();
        let root = *blake3::hash(b"root").as_bytes();
        let enc = EncryptedMetadata::encrypt(&pk, root, seed).unwrap();
        let pt = enc.decrypt(&sk).unwrap();
        assert_eq!(pt.root, root);
        assert_eq!(pt.seed, seed);
    }
}


