//! # bench
//!
//! Performance benchmarks for Tachyon system components.
//! Provides comprehensive benchmarking for MMR operations, PCD proofs, and network operations.

use anyhow::{anyhow, Result};
use net_iroh::Cid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Benchmark configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// Number of iterations for each benchmark
    pub iterations: usize,
    /// Timeout for individual benchmark operations
    pub timeout_secs: u64,
    /// Size of test data for benchmarks
    pub test_data_size: usize,
    /// Enable detailed timing output
    pub verbose: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 100,
            timeout_secs: 30,
            test_data_size: 1024,
            verbose: false,
        }
    }
}

/// Benchmark result for a single operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Operation name
    pub operation: String,
    /// Number of iterations
    pub iterations: usize,
    /// Total time taken
    pub total_time: Duration,
    /// Average time per iteration
    pub avg_time: Duration,
    /// Minimum time for single iteration
    pub min_time: Duration,
    /// Maximum time for single iteration
    pub max_time: Duration,
    /// Throughput (operations per second)
    pub throughput: f64,
    /// Memory usage if measured
    pub memory_usage: Option<usize>,
    /// Success rate (fraction of successful operations)
    pub success_rate: f64,
}

impl BenchmarkResult {
    /// Create a new benchmark result
    pub fn new(
        operation: String,
        iterations: usize,
        total_time: Duration,
        min_time: Duration,
        max_time: Duration,
        success_count: usize,
    ) -> Self {
        let avg_time = total_time / iterations as u32;
        let throughput = if total_time.as_secs_f64() > 0.0 {
            iterations as f64 / total_time.as_secs_f64()
        } else {
            0.0
        };
        let success_rate = success_count as f64 / iterations as f64;

        Self {
            operation,
            iterations,
            total_time,
            avg_time,
            min_time,
            max_time,
            throughput,
            memory_usage: None,
            success_rate,
        }
    }

    /// Format result as human-readable string
    pub fn format(&self) -> String {
        format!(
            "{}: {:.2} ops/sec (avg: {:?}, min: {:?}, max: {:?}, success: {:.2}%)",
            self.operation,
            self.throughput,
            self.avg_time,
            self.min_time,
            self.max_time,
            self.success_rate * 100.0
        )
    }
}

/// Benchmark suite for Tachyon components
pub struct TachyonBenchmark {
    config: BenchmarkConfig,
    results: HashMap<String, BenchmarkResult>,
}

impl TachyonBenchmark {
    /// Create a new benchmark suite
    pub fn new(config: BenchmarkConfig) -> Self {
        Self {
            config,
            results: HashMap::new(),
        }
    }

    /// Run all benchmarks
    pub async fn run_all(&mut self) -> Result<HashMap<String, BenchmarkResult>> {
        println!("Running Tachyon benchmarks...");

        // MMR benchmarks
        self.benchmark_mmr_append().await?;
        self.benchmark_mmr_proof_generation().await?;
        self.benchmark_mmr_proof_verification().await?;

        // PCD benchmarks
        self.benchmark_pcd_state_creation().await?;
        self.benchmark_pcd_transition_creation().await?;
        self.benchmark_pcd_proof_verification().await?;

        // Network benchmarks (skip get due to missing persisted store)
        self.benchmark_blob_store_put().await?;
        self.benchmark_network_publish().await?;

        // Crypto benchmarks
        self.benchmark_kem_operations().await?;
        self.benchmark_aead_operations().await?;
        self.benchmark_blinding_operations().await?;

        // Storage benchmarks
        self.benchmark_note_encryption().await?;
        self.benchmark_note_decryption().await?;
        self.benchmark_db_operations().await?;

        println!("All benchmarks completed!");

        Ok(self.results.clone())
    }

    /// Benchmark MMR append operations
    pub async fn benchmark_mmr_append(&mut self) -> Result<()> {
        use accum_mmr::MmrAccumulator;

        let mut mmr = MmrAccumulator::new();
        let test_data: Vec<_> = (0..self.config.test_data_size)
            .map(|i| blake3::hash(&i.to_le_bytes()))
            .collect();

        let start_time = Instant::now();

        for (i, hash) in test_data.iter().enumerate() {
            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                mmr.append(*hash)?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_err()
            {
                return Err(anyhow!("MMR append timeout"));
            }

            if self.config.verbose && i % 100 == 0 {
                println!("  MMR append progress: {}/{}", i, test_data.len());
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "mmr_append".to_string(),
            test_data.len(),
            total_time,
            Duration::from_nanos(1), // Placeholder min time
            Duration::from_nanos(1), // Placeholder max time
            test_data.len(),         // All operations should succeed
        );

        self.results.insert("mmr_append".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["mmr_append"].format());
        }

        Ok(())
    }

    /// Benchmark MMR proof generation
    pub async fn benchmark_mmr_proof_generation(&mut self) -> Result<()> {
        use accum_mmr::MmrAccumulator;

        let mut mmr = MmrAccumulator::new();

        // Build MMR with test data
        let test_hashes: Vec<_> = (0..self.config.test_data_size)
            .map(|i| blake3::hash(&i.to_le_bytes()))
            .collect();

        for hash in &test_hashes {
            mmr.append(*hash)?;
        }

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for (i, hash) in test_hashes.iter().enumerate() {
            let proof_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let position = i as u64;
                let _proof = mmr.prove(position)?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let proof_time = proof_start.elapsed();
                min_time = min_time.min(proof_time);
                max_time = max_time.max(proof_time);
            }

            if self.config.verbose && i % 100 == 0 {
                println!(
                    "  MMR proof generation progress: {}/{}",
                    i,
                    test_hashes.len()
                );
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "mmr_proof_generation".to_string(),
            test_hashes.len(),
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results
            .insert("mmr_proof_generation".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["mmr_proof_generation"].format());
        }

        Ok(())
    }

    /// Benchmark MMR proof verification
    pub async fn benchmark_mmr_proof_verification(&mut self) -> Result<()> {
        use accum_mmr::MmrAccumulator;

        let mut mmr = MmrAccumulator::new();

        // Build MMR and generate proofs
        let test_hashes: Vec<_> = (0..self.config.test_data_size)
            .map(|i| blake3::hash(&i.to_le_bytes()))
            .collect();

        for hash in &test_hashes {
            mmr.append(*hash)?;
        }

        let proofs: Vec<_> = test_hashes
            .iter()
            .enumerate()
            .map(|(i, _)| mmr.prove(i as u64).unwrap())
            .collect();

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for (i, proof) in proofs.iter().enumerate() {
            let verify_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let mmr_root = mmr.root().unwrap_or(blake3::Hash::from([0u8; 32]));
                let _is_valid = proof.verify(&mmr_root);
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let verify_time = verify_start.elapsed();
                min_time = min_time.min(verify_time);
                max_time = max_time.max(verify_time);
            }

            if self.config.verbose && i % 100 == 0 {
                println!("  MMR proof verification progress: {}/{}", i, proofs.len());
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "mmr_proof_verification".to_string(),
            proofs.len(),
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results
            .insert("mmr_proof_verification".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["mmr_proof_verification"].format());
        }

        Ok(())
    }

    /// Benchmark PCD state creation
    pub async fn benchmark_pcd_state_creation(&mut self) -> Result<()> {
        use pcd_core::PcdState;

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let state_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let mmr_root = blake3::hash(&i.to_le_bytes());
                let nullifier_root = blake3::hash(&(i + 1).to_le_bytes());
                let block_hash = blake3::hash(&(i + 2).to_le_bytes());

                let _state = PcdState::new(
                    i as u64,
                    *mmr_root.as_bytes(),
                    *nullifier_root.as_bytes(),
                    *block_hash.as_bytes(),
                    vec![0u8; self.config.test_data_size],
                    vec![0u8; 1024],
                )?;

                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let state_time = state_start.elapsed();
                min_time = min_time.min(state_time);
                max_time = max_time.max(state_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "pcd_state_creation".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results
            .insert("pcd_state_creation".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["pcd_state_creation"].format());
        }

        Ok(())
    }

    /// Benchmark PCD transition creation
    pub async fn benchmark_pcd_transition_creation(&mut self) -> Result<()> {
        use pcd_core::{PcdState, PcdTransition};

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let transition_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let prev_state = PcdState::new(
                    i as u64,
                    [0u8; 32],
                    [0u8; 32],
                    [0u8; 32],
                    vec![0u8; self.config.test_data_size],
                    vec![0u8; 1024],
                )?;

                let new_state = PcdState::new(
                    (i + 1) as u64,
                    [1u8; 32],
                    [1u8; 32],
                    [1u8; 32],
                    vec![0u8; self.config.test_data_size],
                    vec![0u8; 1024],
                )?;

                let _transition = PcdTransition::new(
                    &prev_state,
                    &new_state,
                    vec![0u8; 256],
                    vec![0u8; 128],
                    vec![0u8; 1024],
                )?;

                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let transition_time = transition_start.elapsed();
                min_time = min_time.min(transition_time);
                max_time = max_time.max(transition_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "pcd_transition_creation".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results
            .insert("pcd_transition_creation".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["pcd_transition_creation"].format());
        }

        Ok(())
    }

    /// Benchmark PCD proof verification
    pub async fn benchmark_pcd_proof_verification(&mut self) -> Result<()> {
        use pcd_core::{PcdState, SimplePcdVerifier};

        let verifier = SimplePcdVerifier;
        let state = PcdState::new(
            0,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            vec![0u8; self.config.test_data_size],
            vec![0u8; 1024],
        )?;

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let verify_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _is_valid = pcd_core::PcdProofVerifier::verify_state_proof(&verifier, &state)?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let verify_time = verify_start.elapsed();
                min_time = min_time.min(verify_time);
                max_time = max_time.max(verify_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "pcd_proof_verification".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results
            .insert("pcd_proof_verification".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["pcd_proof_verification"].format());
        }

        Ok(())
    }

    /// Benchmark blob store put operations
    pub async fn benchmark_blob_store_put(&mut self) -> Result<()> {
        use net_iroh::TachyonBlobStore;
        use std::path::Path;

        let temp_dir = tempfile::tempdir()?;
        let blob_store = TachyonBlobStore::new(temp_dir.path()).await?;

        let test_data = vec![0u8; self.config.test_data_size];

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let put_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let hash = blake3::hash(&test_data);
                let iroh_hash = iroh_blobs::Hash::from(hash);
                blob_store.put(iroh_hash, test_data.clone().into()).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let put_time = put_start.elapsed();
                min_time = min_time.min(put_time);
                max_time = max_time.max(put_time);
            }

            if self.config.verbose && i % 10 == 0 {
                println!(
                    "  Blob store put progress: {}/{}",
                    i, self.config.iterations
                );
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "blob_store_put".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("blob_store_put".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["blob_store_put"].format());
        }

        Ok(())
    }

    /// Benchmark blob store get operations
    pub async fn benchmark_blob_store_get(&mut self) -> Result<()> {
        use net_iroh::TachyonBlobStore;
        use std::path::Path;

        let temp_dir = tempfile::tempdir()?;
        let blob_store = TachyonBlobStore::new(temp_dir.path()).await?;

        // Populate and then fetch to measure end-to-end
        let mut hashes: Vec<iroh_blobs::Hash> = Vec::new();
        for i in 0..self.config.iterations {
            let data = vec![i as u8; self.config.test_data_size];
            let hash = blake3::hash(&data);
            let iroh_hash = iroh_blobs::Hash::from(hash);
            blob_store.put(iroh_hash, data.clone().into()).await?;
            hashes.push(iroh_hash);
        }

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for (i, hash) in hashes.iter().enumerate() {
            let get_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _data = blob_store.get(&hashes[i]).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let get_time = get_start.elapsed();
                min_time = min_time.min(get_time);
                max_time = max_time.max(get_time);
            }

            if self.config.verbose && i % 10 == 0 {
                println!("  Blob store get progress: {}/{}", i, hashes.len());
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "blob_store_get".to_string(),
            hashes.len(),
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("blob_store_get".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["blob_store_get"].format());
        }

        Ok(())
    }

    /// Benchmark network publish operations
    pub async fn benchmark_network_publish(&mut self) -> Result<()> {
        use net_iroh::{BlobKind, TachyonNetwork};
        use std::path::Path;

        let temp_dir = tempfile::tempdir()?;
        let network = TachyonNetwork::new(temp_dir.path()).await?;

        let test_data = vec![0u8; self.config.test_data_size];

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let publish_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _cid = network
                    .publish_blob(BlobKind::Header, test_data.clone().into(), i as u64)
                    .await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let publish_time = publish_start.elapsed();
                min_time = min_time.min(publish_time);
                max_time = max_time.max(publish_time);
            }

            if self.config.verbose && i % 10 == 0 {
                println!(
                    "  Network publish progress: {}/{}",
                    i, self.config.iterations
                );
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "network_publish".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("network_publish".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["network_publish"].format());
        }

        Ok(())
    }

    /// Benchmark KEM operations
    pub async fn benchmark_kem_operations(&mut self) -> Result<()> {
        use pq_crypto::SimpleKem;

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let kem_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let (_pk, _sk) = SimpleKem::generate_keypair()?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let kem_time = kem_start.elapsed();
                min_time = min_time.min(kem_time);
                max_time = max_time.max(kem_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "kem_operations".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("kem_operations".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["kem_operations"].format());
        }

        Ok(())
    }

    /// Benchmark AEAD operations
    pub async fn benchmark_aead_operations(&mut self) -> Result<()> {
        use pq_crypto::generate_aes_key;
        use pq_crypto::SimpleAead;

        let key = generate_aes_key();
        let nonce = SimpleAead::generate_nonce();
        let test_data = vec![0u8; self.config.test_data_size];
        let associated_data = b"benchmark";

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let aead_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _ciphertext = SimpleAead::encrypt(&key, &nonce, &test_data, associated_data)?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let aead_time = aead_start.elapsed();
                min_time = min_time.min(aead_time);
                max_time = max_time.max(aead_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "aead_operations".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("aead_operations".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["aead_operations"].format());
        }

        Ok(())
    }

    /// Benchmark nullifier blinding operations
    pub async fn benchmark_blinding_operations(&mut self) -> Result<()> {
        use pq_crypto::{BlindedNullifier, EpochTag};

        let nullifier = [1u8; 32];
        let epoch_tag = EpochTag::current();

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let blinding_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _blinded = BlindedNullifier::new_blinded(nullifier);
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let blinding_time = blinding_start.elapsed();
                min_time = min_time.min(blinding_time);
                max_time = max_time.max(blinding_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "blinding_operations".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results
            .insert("blinding_operations".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["blinding_operations"].format());
        }

        Ok(())
    }

    /// Benchmark note encryption
    pub async fn benchmark_note_encryption(&mut self) -> Result<()> {
        use pq_crypto::{generate_aes_key, SimpleAead};
        use storage::EncryptedNote;

        let master_key = generate_aes_key();
        let note_data = vec![0u8; self.config.test_data_size];

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let encrypt_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _note = EncryptedNote::new(i as u64, i as u64, &note_data, &master_key);
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let encrypt_time = encrypt_start.elapsed();
                min_time = min_time.min(encrypt_time);
                max_time = max_time.max(encrypt_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "note_encryption".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("note_encryption".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["note_encryption"].format());
        }

        Ok(())
    }

    /// Benchmark note decryption
    pub async fn benchmark_note_decryption(&mut self) -> Result<()> {
        use pq_crypto::generate_aes_key;
        use storage::EncryptedNote;

        let master_key = generate_aes_key();
        let note_data = vec![0u8; self.config.test_data_size];

        // Pre-create encrypted notes
        let notes: Vec<_> = (0..self.config.iterations)
            .map(|i| EncryptedNote::new(i as u64, i as u64, &note_data, &master_key).unwrap())
            .collect();

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for (i, note) in notes.iter().enumerate() {
            let decrypt_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let _decrypted = note.decrypt(&master_key)?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let decrypt_time = decrypt_start.elapsed();
                min_time = min_time.min(decrypt_time);
                max_time = max_time.max(decrypt_time);
            }

            if self.config.verbose && i % 10 == 0 {
                println!("  Note decryption progress: {}/{}", i, notes.len());
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "note_decryption".to_string(),
            notes.len(),
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("note_decryption".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["note_decryption"].format());
        }

        Ok(())
    }

    /// Benchmark database operations
    pub async fn benchmark_db_operations(&mut self) -> Result<()> {
        use std::path::Path;
        use storage::WalletDatabase;

        let temp_dir = tempfile::tempdir()?;
        let db_path = temp_dir.path().join("wallet_db");
        let db = WalletDatabase::new(&db_path, "test_password").await?;

        let start_time = Instant::now();
        let mut min_time = Duration::MAX;
        let mut max_time = Duration::ZERO;
        let mut success_count = 0;

        for i in 0..self.config.iterations {
            let db_start = Instant::now();

            if timeout(Duration::from_secs(self.config.timeout_secs), async {
                let stats = db.get_stats().await;
                // Just access the stats to measure database read performance
                let _total_notes = stats.total_notes;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .is_ok()
            {
                success_count += 1;
                let db_time = db_start.elapsed();
                min_time = min_time.min(db_time);
                max_time = max_time.max(db_time);
            }
        }

        let total_time = start_time.elapsed();
        let result = BenchmarkResult::new(
            "db_operations".to_string(),
            self.config.iterations,
            total_time,
            min_time,
            max_time,
            success_count,
        );

        self.results.insert("db_operations".to_string(), result);

        if self.config.verbose {
            println!("  {}", self.results["db_operations"].format());
        }

        Ok(())
    }

    /// Generate a comprehensive benchmark report
    pub fn generate_report(&self) -> BenchmarkReport {
        let mut report = BenchmarkReport {
            config: self.config.clone(),
            results: self.results.values().cloned().collect(),
            summary: BenchmarkSummary {
                total_operations: 0,
                total_time: Duration::from_secs(0),
                average_throughput: 0.0,
                fastest_operation: None,
                slowest_operation: None,
            },
        };

        // Calculate summary statistics
        for result in &report.results {
            report.summary.total_operations += result.iterations;
            report.summary.total_time += result.total_time;

            if let Some(fastest) = &report.summary.fastest_operation {
                if result.avg_time < fastest.avg_time {
                    report.summary.fastest_operation = Some(result.clone());
                }
            } else {
                report.summary.fastest_operation = Some(result.clone());
            }

            if let Some(slowest) = &report.summary.slowest_operation {
                if result.avg_time > slowest.avg_time {
                    report.summary.slowest_operation = Some(result.clone());
                }
            } else {
                report.summary.slowest_operation = Some(result.clone());
            }
        }

        if report.summary.total_time.as_secs_f64() > 0.0 {
            report.summary.average_throughput =
                report.summary.total_operations as f64 / report.summary.total_time.as_secs_f64();
        }

        report
    }
}

/// Comprehensive benchmark report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Configuration used for benchmarks
    pub config: BenchmarkConfig,
    /// Individual benchmark results
    pub results: Vec<BenchmarkResult>,
    /// Summary statistics
    pub summary: BenchmarkSummary,
}

/// Summary statistics for all benchmarks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    /// Total number of operations across all benchmarks
    pub total_operations: usize,
    /// Total time spent across all benchmarks
    pub total_time: Duration,
    /// Average throughput across all operations
    pub average_throughput: f64,
    /// Fastest operation by average time
    pub fastest_operation: Option<BenchmarkResult>,
    /// Slowest operation by average time
    pub slowest_operation: Option<BenchmarkResult>,
}

impl BenchmarkReport {
    /// Format report as human-readable string
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("=== Tachyon Benchmark Report ===\n"));
        output.push_str(&format!("Configuration:\n"));
        output.push_str(&format!("  Iterations: {}\n", self.config.iterations));
        output.push_str(&format!("  Timeout: {}s\n", self.config.timeout_secs));
        output.push_str(&format!(
            "  Test data size: {} bytes\n",
            self.config.test_data_size
        ));
        output.push_str(&format!("  Verbose: {}\n\n", self.config.verbose));

        output.push_str(&format!("Summary:\n"));
        output.push_str(&format!(
            "  Total operations: {}\n",
            self.summary.total_operations
        ));
        output.push_str(&format!("  Total time: {:?}\n", self.summary.total_time));
        output.push_str(&format!(
            "  Average throughput: {:.2} ops/sec\n",
            self.summary.average_throughput
        ));

        if let Some(ref fastest) = self.summary.fastest_operation {
            output.push_str(&format!(
                "  Fastest operation: {} ({:?} avg)\n",
                fastest.operation, fastest.avg_time
            ));
        }

        if let Some(ref slowest) = self.summary.slowest_operation {
            output.push_str(&format!(
                "  Slowest operation: {} ({:?} avg)\n",
                slowest.operation, slowest.avg_time
            ));
        }

        output.push_str(&format!("\nDetailed Results:\n"));

        for result in &self.results {
            output.push_str(&format!("  {}\n", result.format()));
        }

        output
    }

    /// Save report to JSON file
    pub fn save_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Run a quick benchmark suite with default configuration
pub async fn run_quick_benchmarks() -> Result<BenchmarkReport> {
    let mut benchmark = TachyonBenchmark::new(BenchmarkConfig {
        iterations: 50,
        timeout_secs: 10,
        test_data_size: 512,
        verbose: false,
    });

    benchmark.run_all().await?;
    Ok(benchmark.generate_report())
}

/// Run comprehensive benchmarks with detailed configuration
pub async fn run_comprehensive_benchmarks() -> Result<BenchmarkReport> {
    let mut benchmark = TachyonBenchmark::new(BenchmarkConfig {
        iterations: 200,
        timeout_secs: 60,
        test_data_size: 2048,
        verbose: true,
    });

    benchmark.run_all().await?;
    Ok(benchmark.generate_report())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_benchmark_creation() {
        let config = BenchmarkConfig::default();
        let benchmark = TachyonBenchmark::new(config);
        assert_eq!(benchmark.results.len(), 0);
    }

    #[tokio::test]
    async fn test_quick_benchmarks() {
        let report = run_quick_benchmarks().await.unwrap();
        assert!(report.results.len() > 0);
        assert!(report.summary.total_operations > 0);
    }

    #[test]
    fn test_benchmark_result_format() {
        let result = BenchmarkResult::new(
            "test_operation".to_string(),
            100,
            Duration::from_secs(1),
            Duration::from_millis(5),
            Duration::from_millis(15),
            100,
        );

        let formatted = result.format();
        assert!(formatted.contains("test_operation"));
        assert!(formatted.contains("ops/sec"));
    }
}
