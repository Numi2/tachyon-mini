//! Persistent proof cache with content-addressing
//! Numan Thabit 2025

use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::fs;
use std::io::{Read, Write};

/// Proof type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    Transition,
    Recursion,
    SpendLink,
    TachyAction,
}

/// Metadata for a cached proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub digest: [u8; 32],
    pub proof_type: ProofType,
    pub size_bytes: u64,
    pub created_at: u64,
    pub last_accessed: u64,
    pub access_count: u64,
    pub public_inputs_hash: [u8; 32],
}

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_proofs: u64,
    pub unique_proofs: u64,
    pub total_size_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        if self.hits + self.misses == 0 {
            0.0
        } else {
            self.hits as f64 / (self.hits + self.misses) as f64
        }
    }
}

/// Content-addressed proof cache
pub struct ProofCache {
    cache_dir: PathBuf,
    max_size_bytes: u64,
    metadata: Arc<RwLock<HashMap<[u8; 32], ProofMetadata>>>,
    stats: Arc<RwLock<CacheStats>>,
}

impl ProofCache {
    /// Create a new proof cache
    pub fn new<P: AsRef<Path>>(cache_dir: P, max_size_bytes: u64) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        fs::create_dir_all(&cache_dir)?;
        fs::create_dir_all(cache_dir.join("blobs"))?;
        
        // Create shard directories (00-ff)
        for i in 0..256 {
            fs::create_dir_all(cache_dir.join("blobs").join(format!("{:02x}", i)))?;
        }
        
        let mut cache = Self {
            cache_dir,
            max_size_bytes,
            metadata: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        };
        
        // Load existing metadata
        cache.load_metadata()?;
        
        Ok(cache)
    }

    /// Compute content digest for a proof
    pub fn compute_digest(proof: &[u8]) -> [u8; 32] {
        blake3::hash(proof).into()
    }

    /// Compute hash of public inputs
    fn hash_public_inputs(inputs: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize().into()
    }

    /// Get blob path for a digest
    fn blob_path(&self, digest: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(digest);
        self.cache_dir
            .join("blobs")
            .join(&hex[0..2])
            .join(&hex)
    }

    /// Insert a proof into the cache
    pub fn insert(
        &mut self,
        proof: &[u8],
        proof_type: ProofType,
        public_inputs: &[[u8; 32]],
    ) -> Result<[u8; 32]> {
        let digest = Self::compute_digest(proof);
        
        // Check if already cached
        if self.metadata.read().contains_key(&digest) {
            // Update access time
            if let Some(meta) = self.metadata.write().get_mut(&digest) {
                meta.last_accessed = Self::current_time();
                meta.access_count += 1;
            }
            self.stats.write().total_proofs += 1;
            return Ok(digest);
        }
        
        // Write proof blob
        let blob_path = self.blob_path(&digest);
        let mut file = fs::File::create(blob_path)?;
        file.write_all(proof)?;
        file.sync_all()?;
        
        // Create metadata
        let metadata = ProofMetadata {
            digest,
            proof_type,
            size_bytes: proof.len() as u64,
            created_at: Self::current_time(),
            last_accessed: Self::current_time(),
            access_count: 1,
            public_inputs_hash: Self::hash_public_inputs(public_inputs),
        };
        
        // Update cache state
        self.metadata.write().insert(digest, metadata);
        
        let mut stats = self.stats.write();
        stats.total_proofs += 1;
        stats.unique_proofs += 1;
        stats.total_size_bytes += proof.len() as u64;
        
        // Check if eviction needed
        if stats.total_size_bytes > self.max_size_bytes {
            drop(stats); // Release lock before eviction
            self.evict_lru()?;
        }
        
        Ok(digest)
    }

    /// Retrieve a proof from the cache
    pub fn get(&self, digest: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        // Check metadata
        if !self.metadata.read().contains_key(digest) {
            self.stats.write().misses += 1;
            return Ok(None);
        }
        
        // Update access time
        if let Some(meta) = self.metadata.write().get_mut(digest) {
            meta.last_accessed = Self::current_time();
            meta.access_count += 1;
        }
        
        // Read blob
        let blob_path = self.blob_path(digest);
        if !blob_path.exists() {
            self.stats.write().misses += 1;
            return Ok(None);
        }
        
        let mut file = fs::File::open(blob_path)?;
        let mut proof = Vec::new();
        file.read_to_end(&mut proof)?;
        
        self.stats.write().hits += 1;
        Ok(Some(proof))
    }

    /// Check if a proof exists in the cache
    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.metadata.read().contains_key(digest)
    }

    /// Evict least-recently-used proofs to free space
    pub fn evict_lru(&mut self) -> Result<u64> {
        let mut evicted_bytes = 0u64;
        
        // Get candidates sorted by last_accessed
        let mut candidates: Vec<_> = self.metadata.read()
            .values()
            .cloned()
            .collect();
        candidates.sort_by_key(|m| m.last_accessed);
        
        // Evict until under limit
        for meta in candidates {
            let current_size = self.stats.read().total_size_bytes;
            if current_size <= self.max_size_bytes {
                break;
            }
            
            // Delete blob
            let blob_path = self.blob_path(&meta.digest);
            if blob_path.exists() {
                fs::remove_file(blob_path)?;
            }
            
            // Remove metadata
            self.metadata.write().remove(&meta.digest);
            
            // Update stats
            let mut stats = self.stats.write();
            stats.unique_proofs = stats.unique_proofs.saturating_sub(1);
            stats.total_size_bytes = stats.total_size_bytes.saturating_sub(meta.size_bytes);
            stats.evictions += 1;
            
            evicted_bytes += meta.size_bytes;
        }
        
        Ok(evicted_bytes)
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Load metadata from disk
    fn load_metadata(&mut self) -> Result<()> {
        let blobs_dir = self.cache_dir.join("blobs");
        if !blobs_dir.exists() {
            return Ok(());
        }
        
        // Scan all shard directories
        for entry in fs::read_dir(blobs_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            
            // Scan blobs in this shard
            for blob_entry in fs::read_dir(entry.path())? {
                let blob_entry = blob_entry?;
                if !blob_entry.file_type()?.is_file() {
                    continue;
                }
                
                // Parse digest from filename
                let filename = blob_entry.file_name();
                let filename_str = filename.to_str().ok_or_else(|| anyhow!("Invalid filename"))?;
                let digest_bytes = hex::decode(filename_str)?;
                if digest_bytes.len() != 32 {
                    continue;
                }
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&digest_bytes);
                
                // Get file metadata
                let file_meta = blob_entry.metadata()?;
                let size = file_meta.len();
                
                // Create proof metadata (we don't have all info, use defaults)
                let proof_meta = ProofMetadata {
                    digest,
                    proof_type: ProofType::Transition, // Default
                    size_bytes: size,
                    created_at: 0,
                    last_accessed: 0,
                    access_count: 0,
                    public_inputs_hash: [0u8; 32],
                };
                
                self.metadata.write().insert(digest, proof_meta);
                
                let mut stats = self.stats.write();
                stats.unique_proofs += 1;
                stats.total_size_bytes += size;
            }
        }
        
        Ok(())
    }

    fn current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_proof_cache_basic() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = ProofCache::new(temp_dir.path(), 1024 * 1024).unwrap();
        
        let proof = vec![1, 2, 3, 4, 5];
        let inputs = [[1u8; 32], [2u8; 32]];
        
        // Insert
        let digest = cache.insert(&proof, ProofType::Transition, &inputs).unwrap();
        
        // Retrieve
        let retrieved = cache.get(&digest).unwrap();
        assert_eq!(retrieved, Some(proof));
        
        // Stats
        let stats = cache.stats();
        assert_eq!(stats.unique_proofs, 1);
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn test_proof_cache_deduplication() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = ProofCache::new(temp_dir.path(), 1024 * 1024).unwrap();
        
        let proof = vec![1, 2, 3, 4, 5];
        let inputs = [[1u8; 32]];
        
        // Insert same proof twice
        let digest1 = cache.insert(&proof, ProofType::Transition, &inputs).unwrap();
        let digest2 = cache.insert(&proof, ProofType::Transition, &inputs).unwrap();
        
        assert_eq!(digest1, digest2);
        assert_eq!(cache.stats().unique_proofs, 1);
        assert_eq!(cache.stats().total_proofs, 2);
    }

    #[test]
    fn test_proof_cache_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = ProofCache::new(temp_dir.path(), 100).unwrap(); // Small cache
        
        // Insert proofs until eviction
        for i in 0..10 {
            let proof = vec![i; 50]; // 50 bytes each
            cache.insert(&proof, ProofType::Transition, &[]).unwrap();
        }
        
        let stats = cache.stats();
        assert!(stats.evictions > 0);
        assert!(stats.total_size_bytes <= 100);
    }
}

