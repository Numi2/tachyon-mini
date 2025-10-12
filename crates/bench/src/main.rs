//! Tachyon benchmark binary
//!
//! Command-line interface for running Tachyon performance benchmarks.

use anyhow::Result;
use bench::{
    run_comprehensive_benchmarks, run_quick_benchmarks, BenchmarkConfig, TachyonBenchmark,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tachyon-bench")]
#[command(about = "Tachyon performance benchmarks")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Number of benchmark iterations
    #[arg(short, long, default_value = "100")]
    iterations: usize,

    /// Timeout for individual operations in seconds
    #[arg(short, long, default_value = "30")]
    timeout_secs: u64,

    /// Size of test data in bytes
    #[arg(short, long, default_value = "1024")]
    test_data_size: usize,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output file for benchmark results (JSON)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run quick benchmarks with reduced iterations
    Quick,
    /// Run comprehensive benchmarks with full configuration
    Comprehensive,
    /// Run specific benchmark component
    Component {
        /// Component to benchmark (mmr, pcd, network, crypto, storage)
        #[arg(value_parser = ["mmr", "pcd", "network", "crypto", "storage"])]
        component: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize structured logging (JSON)
    let env_level = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        if cli.verbose { "debug".into() } else { "info".into() }
    });
    std::env::set_var("RUST_LOG", env_level);
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Create benchmark configuration
    let config = BenchmarkConfig {
        iterations: cli.iterations,
        timeout_secs: cli.timeout_secs,
        test_data_size: cli.test_data_size,
        verbose: cli.verbose,
    };

    // Run benchmarks based on command
    let report = match cli.command {
        Commands::Quick => {
            println!("Running quick benchmarks...");
            run_quick_benchmarks().await?
        }
        Commands::Comprehensive => {
            println!("Running comprehensive benchmarks...");
            run_comprehensive_benchmarks().await?
        }
        Commands::Component { component } => {
            println!("Running {} benchmarks...", component);
            run_component_benchmarks(&component, config).await?
        }
    };

    // Output results
    println!("{}", report.format());

    // Save to file if specified
    if let Some(output_path) = cli.output {
        println!("Saving results to: {}", output_path.display());
        report.save_json(output_path.to_str().unwrap())?;
    }

    Ok(())
}

/// Run benchmarks for a specific component
async fn run_component_benchmarks(
    component: &str,
    config: BenchmarkConfig,
) -> Result<bench::BenchmarkReport> {
    let mut benchmark = TachyonBenchmark::new(config);

    match component {
        "mmr" => {
            benchmark.benchmark_mmr_append().await?;
            benchmark.benchmark_mmr_proof_generation().await?;
            benchmark.benchmark_mmr_proof_verification().await?;
        }
        "pcd" => {
            benchmark.benchmark_pcd_state_creation().await?;
            benchmark.benchmark_pcd_transition_creation().await?;
            benchmark.benchmark_pcd_proof_verification().await?;
        }
        "network" => {
            benchmark.benchmark_blob_store_put().await?;
            benchmark.benchmark_blob_store_get().await?;
            benchmark.benchmark_network_publish().await?;
        }
        "crypto" => {
            benchmark.benchmark_kem_operations().await?;
            benchmark.benchmark_aead_operations().await?;
            benchmark.benchmark_blinding_operations().await?;
        }
        "storage" => {
            benchmark.benchmark_note_encryption().await?;
            benchmark.benchmark_note_decryption().await?;
            benchmark.benchmark_db_operations().await?;
        }
        _ => unreachable!(),
    }

    Ok(benchmark.generate_report())
}
