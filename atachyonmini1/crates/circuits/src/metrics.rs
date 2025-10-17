//! Metrics and telemetry instrumentation for Tachyon circuits
//! Numan Thabit 2025
//!
//! Provides production-grade monitoring and observability

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Global metrics collector
static METRICS: once_cell::sync::Lazy<Arc<MetricsCollector>> =
    once_cell::sync::Lazy::new(|| Arc::new(MetricsCollector::new()));

/// Get the global metrics collector
pub fn metrics() -> &'static Arc<MetricsCollector> {
    &METRICS
}

/// Metrics collector for circuit operations
#[derive(Debug)]
pub struct MetricsCollector {
    // Circuit proving metrics
    pub proofs_generated: AtomicU64,
    pub proofs_verified: AtomicU64,
    pub proof_failures: AtomicU64,
    
    // Performance metrics
    pub total_proving_time_ms: AtomicU64,
    pub total_verification_time_ms: AtomicU64,
    
    // Tachygram metrics
    pub tachygrams_created: AtomicU64,
    pub tachygrams_chained: AtomicU64,
    pub tachygram_actions: AtomicU64,
    
    // Accumulator metrics
    pub accumulator_updates: AtomicU64,
    
    // Detailed histograms (stored in write-locked state)
    histograms: RwLock<MetricsHistograms>,
}

#[derive(Debug, Default)]
struct MetricsHistograms {
    proving_times: Vec<Duration>,
    verification_times: Vec<Duration>,
    tachygram_sizes: Vec<usize>,
}

impl MetricsCollector {
    fn new() -> Self {
        Self {
            proofs_generated: AtomicU64::new(0),
            proofs_verified: AtomicU64::new(0),
            proof_failures: AtomicU64::new(0),
            total_proving_time_ms: AtomicU64::new(0),
            total_verification_time_ms: AtomicU64::new(0),
            tachygrams_created: AtomicU64::new(0),
            tachygrams_chained: AtomicU64::new(0),
            tachygram_actions: AtomicU64::new(0),
            accumulator_updates: AtomicU64::new(0),
            histograms: RwLock::new(MetricsHistograms::default()),
        }
    }

    /// Record a proof generation
    pub fn record_proof_generated(&self, duration: Duration) {
        self.proofs_generated.fetch_add(1, Ordering::Relaxed);
        self.total_proving_time_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        self.histograms.write().proving_times.push(duration);
        
        tracing::info!(
            proving_time_ms = duration.as_millis(),
            total_proofs = self.proofs_generated.load(Ordering::Relaxed),
            "Proof generated"
        );
    }

    /// Record a proof verification
    pub fn record_proof_verified(&self, duration: Duration, success: bool) {
        self.proofs_verified.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.proof_failures.fetch_add(1, Ordering::Relaxed);
        }
        self.total_verification_time_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        self.histograms.write().verification_times.push(duration);
        
        tracing::info!(
            verification_time_ms = duration.as_millis(),
            success = success,
            total_verified = self.proofs_verified.load(Ordering::Relaxed),
            "Proof verified"
        );
    }

    /// Record a tachygram creation
    pub fn record_tachygram_created(&self, num_actions: usize) {
        self.tachygrams_created.fetch_add(1, Ordering::Relaxed);
        self.tachygram_actions.fetch_add(num_actions as u64, Ordering::Relaxed);
        self.histograms.write().tachygram_sizes.push(num_actions);
        
        tracing::info!(
            num_actions = num_actions,
            total_tachygrams = self.tachygrams_created.load(Ordering::Relaxed),
            "Tachygram created"
        );
    }

    /// Record a tachygram chain operation
    pub fn record_tachygram_chained(&self) {
        self.tachygrams_chained.fetch_add(1, Ordering::Relaxed);
        
        tracing::debug!(
            total_chained = self.tachygrams_chained.load(Ordering::Relaxed),
            "Tachygram chained"
        );
    }

    /// Record an accumulator update
    pub fn record_accumulator_update(&self) {
        self.accumulator_updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        let histograms = self.histograms.read();
        
        MetricsSnapshot {
            proofs_generated: self.proofs_generated.load(Ordering::Relaxed),
            proofs_verified: self.proofs_verified.load(Ordering::Relaxed),
            proof_failures: self.proof_failures.load(Ordering::Relaxed),
            total_proving_time_ms: self.total_proving_time_ms.load(Ordering::Relaxed),
            total_verification_time_ms: self.total_verification_time_ms.load(Ordering::Relaxed),
            tachygrams_created: self.tachygrams_created.load(Ordering::Relaxed),
            tachygrams_chained: self.tachygrams_chained.load(Ordering::Relaxed),
            tachygram_actions: self.tachygram_actions.load(Ordering::Relaxed),
            accumulator_updates: self.accumulator_updates.load(Ordering::Relaxed),
            avg_proving_time_ms: if !histograms.proving_times.is_empty() {
                histograms.proving_times.iter().sum::<Duration>().as_millis() as u64
                    / histograms.proving_times.len() as u64
            } else {
                0
            },
            avg_verification_time_ms: if !histograms.verification_times.is_empty() {
                histograms.verification_times.iter().sum::<Duration>().as_millis() as u64
                    / histograms.verification_times.len() as u64
            } else {
                0
            },
            avg_tachygram_size: if !histograms.tachygram_sizes.is_empty() {
                histograms.tachygram_sizes.iter().sum::<usize>()
                    / histograms.tachygram_sizes.len()
            } else {
                0
            },
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.proofs_generated.store(0, Ordering::Relaxed);
        self.proofs_verified.store(0, Ordering::Relaxed);
        self.proof_failures.store(0, Ordering::Relaxed);
        self.total_proving_time_ms.store(0, Ordering::Relaxed);
        self.total_verification_time_ms.store(0, Ordering::Relaxed);
        self.tachygrams_created.store(0, Ordering::Relaxed);
        self.tachygrams_chained.store(0, Ordering::Relaxed);
        self.tachygram_actions.store(0, Ordering::Relaxed);
        self.accumulator_updates.store(0, Ordering::Relaxed);
        *self.histograms.write() = MetricsHistograms::default();
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub proofs_generated: u64,
    pub proofs_verified: u64,
    pub proof_failures: u64,
    pub total_proving_time_ms: u64,
    pub total_verification_time_ms: u64,
    pub tachygrams_created: u64,
    pub tachygrams_chained: u64,
    pub tachygram_actions: u64,
    pub accumulator_updates: u64,
    pub avg_proving_time_ms: u64,
    pub avg_verification_time_ms: u64,
    pub avg_tachygram_size: usize,
}

impl MetricsSnapshot {
    /// Export metrics in Prometheus format
    pub fn to_prometheus(&self) -> String {
        format!(
            r#"# HELP tachyon_proofs_generated_total Total number of proofs generated
# TYPE tachyon_proofs_generated_total counter
tachyon_proofs_generated_total {}

# HELP tachyon_proofs_verified_total Total number of proofs verified
# TYPE tachyon_proofs_verified_total counter
tachyon_proofs_verified_total {}

# HELP tachyon_proof_failures_total Total number of proof verification failures
# TYPE tachyon_proof_failures_total counter
tachyon_proof_failures_total {}

# HELP tachyon_proving_time_ms_total Total time spent proving (milliseconds)
# TYPE tachyon_proving_time_ms_total counter
tachyon_proving_time_ms_total {}

# HELP tachyon_verification_time_ms_total Total time spent verifying (milliseconds)
# TYPE tachyon_verification_time_ms_total counter
tachyon_verification_time_ms_total {}

# HELP tachyon_avg_proving_time_ms Average proving time (milliseconds)
# TYPE tachyon_avg_proving_time_ms gauge
tachyon_avg_proving_time_ms {}

# HELP tachyon_avg_verification_time_ms Average verification time (milliseconds)
# TYPE tachyon_avg_verification_time_ms gauge
tachyon_avg_verification_time_ms {}

# HELP tachyon_tachygrams_created_total Total number of tachygrams created
# TYPE tachyon_tachygrams_created_total counter
tachyon_tachygrams_created_total {}

# HELP tachyon_tachygrams_chained_total Total number of tachygram chain operations
# TYPE tachyon_tachygrams_chained_total counter
tachyon_tachygrams_chained_total {}

# HELP tachyon_tachygram_actions_total Total number of actions in all tachygrams
# TYPE tachyon_tachygram_actions_total counter
tachyon_tachygram_actions_total {}

# HELP tachyon_accumulator_updates_total Total number of accumulator updates
# TYPE tachyon_accumulator_updates_total counter
tachyon_accumulator_updates_total {}

# HELP tachyon_avg_tachygram_size Average number of actions per tachygram
# TYPE tachyon_avg_tachygram_size gauge
tachyon_avg_tachygram_size {}
"#,
            self.proofs_generated,
            self.proofs_verified,
            self.proof_failures,
            self.total_proving_time_ms,
            self.total_verification_time_ms,
            self.avg_proving_time_ms,
            self.avg_verification_time_ms,
            self.tachygrams_created,
            self.tachygrams_chained,
            self.tachygram_actions,
            self.accumulator_updates,
            self.avg_tachygram_size,
        )
    }
}

/// RAII guard for automatic timing
pub struct TimingGuard {
    start: Instant,
    metric_type: MetricType,
}

pub enum MetricType {
    Proving,
    Verification,
}

impl TimingGuard {
    pub fn new(metric_type: MetricType) -> Self {
        Self {
            start: Instant::now(),
            metric_type,
        }
    }
    
    pub fn finish(self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        match self.metric_type {
            MetricType::Proving => metrics().record_proof_generated(elapsed),
            MetricType::Verification => metrics().record_proof_verified(elapsed, true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_snapshot() {
        let collector = MetricsCollector::new();
        
        collector.record_proof_generated(Duration::from_millis(100));
        collector.record_proof_verified(Duration::from_millis(50), true);
        collector.record_tachygram_created(5);
        
        let snapshot = collector.snapshot();
        
        assert_eq!(snapshot.proofs_generated, 1);
        assert_eq!(snapshot.proofs_verified, 1);
        assert_eq!(snapshot.tachygrams_created, 1);
        assert_eq!(snapshot.tachygram_actions, 5);
    }

    #[test]
    fn test_prometheus_export() {
        let snapshot = MetricsSnapshot {
            proofs_generated: 10,
            proofs_verified: 9,
            proof_failures: 1,
            total_proving_time_ms: 1000,
            total_verification_time_ms: 450,
            tachygrams_created: 5,
            tachygrams_chained: 3,
            tachygram_actions: 25,
            accumulator_updates: 25,
            avg_proving_time_ms: 100,
            avg_verification_time_ms: 50,
            avg_tachygram_size: 5,
        };
        
        let prom = snapshot.to_prometheus();
        assert!(prom.contains("tachyon_proofs_generated_total 10"));
        assert!(prom.contains("tachyon_avg_proving_time_ms 100"));
    }
}

