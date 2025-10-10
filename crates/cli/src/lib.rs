//! # cli
//!
//! Command-line interface for Tachyon wallet and network tools.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::Path;
use tracing_subscriber;
use wallet::{TachyonWallet, WalletConfig};
use bytes::Bytes;
use net_iroh::{BlobKind, TachyonNetwork};
use node_ext::{NodeConfig, NetworkConfig};
use header_sync::{HeaderSyncConfig as HsConfig, HeaderSyncManager};

/// Tachyon CLI application
#[derive(Parser)]
#[command(name = "tachyon")]
#[command(about = "A Tachyon-style Zcash system CLI")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Data directory
    #[arg(short, long, default_value = "./tachyon_data")]
    pub data_dir: String,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        wallet_command: WalletCommands,
    },
    /// Network operations
    Network {
        #[command(subcommand)]
        network_command: NetworkCommands,
    },
    /// Header sync operations
    HeaderSync {
        #[command(subcommand)]
        hs_command: HeaderSyncCommands,
    },
}

/// Wallet-specific commands
#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Wallet name
        #[arg(short, long)]
        name: String,

        /// Master password
        #[arg(short, long)]
        password: String,

        /// Database path (optional)
        #[arg(short, long)]
        db_path: Option<String>,
    },
    /// Show our OOB recipient URI
    OobUri {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Parse an OOB payment URI (json) and process
    OobParse {
        /// Payment JSON (URI-decoded)
        #[arg(short, long)]
        payment_json: String,

        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Show wallet information
    Info {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// List wallet notes
    ListNotes {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,

        /// Show only unspent notes
        #[arg(short, long)]
        unspent_only: bool,
    },
    /// Create an out-of-band payment
    CreatePayment {
        /// Recipient's Kyber public key (hex)
        #[arg(short, long)]
        recipient_pk: String,

        /// Note value
        #[arg(short, long)]
        value: u64,

        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Receive an out-of-band payment
    ReceivePayment {
        /// Payment data (hex)
        #[arg(short, long)]
        payment_data: String,

        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Sync wallet state
    Sync {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
}

/// Network-specific commands
#[derive(Subcommand)]
pub enum NetworkCommands {
    /// Start a network node
    Node {
        /// Node data directory
        #[arg(short, long)]
        data_dir: String,

        /// Listen address
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        listen_addr: String,

        /// Bootstrap nodes (comma-separated)
        #[arg(short, long)]
        bootstrap_nodes: Option<String>,
    },
    /// Publish a blob to the network
    Publish {
        /// Blob file path
        #[arg(short, long)]
        file: String,

        /// Blob kind (commitment_delta, nullifier_delta, pcd_transition, header, checkpoint)
        #[arg(short, long)]
        kind: String,

        /// Block height
        #[arg(short, long)]
        height: u64,
    },
}

/// Header sync commands
#[derive(Subcommand)]
pub enum HeaderSyncCommands {
    /// Bootstrap from trusted checkpoints (Zcash-tuned)
    Bootstrap {
        /// Data directory for header sync
        #[arg(short, long, default_value = "./header_data")]
        data_dir: String,
        /// Comma-separated HTTPS checkpoint servers
        #[arg(short, long)]
        checkpoint_servers: Option<String>,
        /// Minimum checkpoint signatures required
        #[arg(long, default_value_t = 2)]
        min_sigs: usize,
        /// Trusted checkpoint public keys (hex, comma-separated)
        #[arg(long)]
        trusted_pks: Option<String>,
    },
    /// Sync headers to latest announcements
    SyncOnce {
        /// Data directory for header sync
        #[arg(short, long, default_value = "./header_data")]
        data_dir: String,
        /// Max batch size
        #[arg(long, default_value_t = 16)]
        max_batch_size: usize,
    },
}

/// Run the CLI application
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Execute command
    match cli.command {
        Commands::Wallet { wallet_command } => {
            execute_wallet_command(wallet_command, &cli.data_dir).await
        }
        Commands::Network { network_command } => execute_network_command(network_command).await,
        Commands::HeaderSync { hs_command } => execute_header_sync_command(hs_command).await,
    }
}

/// Execute wallet commands
async fn execute_wallet_command(command: WalletCommands, data_dir: &str) -> Result<()> {
    match command {
        WalletCommands::Create {
            name,
            password,
            db_path,
        } => {
            let db_path = db_path.unwrap_or_else(|| format!("{}/wallets/{}", data_dir, name));

            println!("Creating wallet '{}' at {}", name, db_path);

            // Create wallet directory structure
            std::fs::create_dir_all(&db_path)?;

            // Initialize wallet database and genesis PCD state
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            // Allow insecure defaults for CLI bootstrap only
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");

            let mut wallet = TachyonWallet::new(cfg).await?;
            wallet.initialize().await?;

            println!("Wallet created successfully!");
        }
        WalletCommands::OobUri { db_path, password } => {
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let pk = wallet.get_oob_public_key().await;
            let uri = format!(
                "tachyon:oobpay?pk=0x{}&scheme=kyber768",
                hex::encode(pk.as_bytes())
            );
            println!("OOB Recipient URI:\n{}", uri);
        }
        WalletCommands::OobParse {
            payment_json,
            db_path,
            password,
        } => {
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let payment: pq_crypto::OutOfBandPayment = serde_json::from_str(&payment_json)?;
            let hash = wallet.receive_oob_payment(payment).await?;
            if let Some(note) = wallet.process_oob_payment(&hash).await? {
                println!(
                    "Payment processed: value={} height={} pos={}",
                    note.value, note.block_height, note.position
                );
            } else {
                println!("No matching payment found");
            }
        }
        WalletCommands::Info { db_path, password } => {
            println!("Loading wallet from {}", db_path);

            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                println!("Use 'tachyon wallet create' to create a new wallet");
                return Ok(());
            }

            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();

            // Allow insecure for CLI info
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");

            let wallet = TachyonWallet::new(cfg).await?;
            let stats = wallet.get_stats().await?;
            println!("Wallet Status: Initialized");
            println!("Database path: {}", db_path);
            println!(
                "Notes: total={}, unspent={}, spent={}",
                stats.db_stats.total_notes,
                stats.db_stats.unspent_notes,
                stats.db_stats.spent_notes
            );
            println!(
                "Current anchor height: {}",
                stats.current_anchor_height.unwrap_or(0)
            );
        }
        WalletCommands::ListNotes {
            db_path,
            password,
            unspent_only,
        } => {
            println!("Loading wallet from {}", db_path);

            // Check if wallet exists
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }

            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let notes = if unspent_only {
                wallet.list_unspent_notes().await?
            } else {
                wallet.list_notes().await?
            };
            println!("Wallet Notes ({}):", notes.len());
            for (i, n) in notes.iter().enumerate() {
                println!(
                    "  #{} value={} spent={} pos={} height={}",
                    i, n.value, n.is_spent, n.position, n.block_height
                );
            }
        }
        WalletCommands::CreatePayment {
            recipient_pk,
            value,
            db_path,
            password,
        } => {
            println!("Creating out-of-band payment");
            println!("  Recipient: {}", recipient_pk);
            println!("  Value: {}", value);
            println!("  Database: {}", db_path);

            // Check if wallet exists
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }

            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;

            let recipient_pk_bytes = hex::decode(recipient_pk.trim_start_matches("0x"))?;
            let recipient_pk = pq_crypto::KyberPublicKey::from_bytes(&recipient_pk_bytes)?;

            // Compose note metadata: [commitment(32) | value(8) | recipient(32) | rseed(32) | memo_len(2) | memo(..)]
            // Derive a simple demo recipient hash from the user's provided recipient_pk
            let recipient_bytes = blake3::hash(recipient_pk.as_bytes());

            // Create a synthetic note commitment bound to value and recipient
            let mut h_commit = blake3::Hasher::new();
            h_commit.update(b"note_commitment:v1");
            h_commit.update(&value.to_le_bytes());
            h_commit.update(recipient_bytes.as_bytes());
            let commitment = h_commit.finalize();

            // Derive rseed deterministically for demo
            let mut h_rseed = blake3::Hasher::new();
            h_rseed.update(b"rseed:v1");
            h_rseed.update(commitment.as_bytes());
            let rseed = h_rseed.finalize();

            let mut meta = Vec::new();
            meta.extend_from_slice(commitment.as_bytes());
            meta.extend_from_slice(&value.to_le_bytes());
            meta.extend_from_slice(recipient_bytes.as_bytes());
            meta.extend_from_slice(rseed.as_bytes());
            meta.extend_from_slice(&(0u16).to_le_bytes()); // memo length 0

            let payment = wallet
                .create_oob_payment(recipient_pk, meta, b"cli_payment".to_vec())
                .await?;
            let json = serde_json::to_string_pretty(&payment)?;
            println!("Payment JSON (share with recipient via OOB):\n{}", json);
        }
        WalletCommands::ReceivePayment {
            payment_data,
            db_path,
            password,
        } => {
            println!("Processing out-of-band payment");

            // Check if wallet exists
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }

            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;

            let payment: pq_crypto::OutOfBandPayment = serde_json::from_str(&payment_data)?;
            let hash = wallet.receive_oob_payment(payment).await?;
            if let Some(note) = wallet.process_oob_payment(&hash).await? {
                println!(
                    "Payment processed: value={} height={} pos={}",
                    note.value, note.block_height, note.position
                );
            } else {
                println!("No matching payment found");
            }
        }
        WalletCommands::Sync { db_path, password } => {
            println!("Syncing wallet state");

            // Check if wallet exists
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }

            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            wallet.sync().await?;
            println!("Wallet synced successfully");
        }
    }

    Ok(())
}

/// Execute network commands
async fn execute_network_command(command: NetworkCommands) -> Result<()> {
    match command {
        NetworkCommands::Node {
            data_dir,
            listen_addr,
            bootstrap_nodes,
        } => {
            println!("Starting Tachyon node");
            println!("Data directory: {}", data_dir);
            println!("Listen address: {}", listen_addr);

            let bootstrap_list = bootstrap_nodes
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();

            // Ensure data dir exists
            std::fs::create_dir_all(&data_dir)?;

            // Build node config
            let mut net_cfg = NetworkConfig::default();
            net_cfg.data_dir = data_dir.clone();
            net_cfg.listen_addr = Some(listen_addr.clone());
            net_cfg.bootstrap_nodes = bootstrap_list;

            let mut node_cfg = NodeConfig::default();
            node_cfg.network_config = net_cfg;

            // Start node
            let node = node_ext::TachyonNode::new(node_cfg).await?;
            println!("Node started. Node ID: {}", node.node_id());
            println!("Press Ctrl-C to stop.");

            // Wait for Ctrl-C
            tokio::signal::ctrl_c().await?;
            node.shutdown().await?;
            println!("Node stopped.");
        }
        NetworkCommands::Publish { file, kind, height } => {
            // Check file exists and read
            let path = Path::new(&file);
            if !path.exists() {
                return Err(anyhow!("File not found: {}", file));
            }
            let bytes = std::fs::read(path)?;

            // Parse kind
            let kind_enum = match kind.to_lowercase().as_str() {
                "commitment_delta" | "commitment-delta" => BlobKind::CommitmentDelta,
                "nullifier_delta" | "nullifier-delta" => BlobKind::NullifierDelta,
                "pcd_transition" | "pcd-transition" => BlobKind::PcdTransition,
                "header" => BlobKind::Header,
                "checkpoint" => BlobKind::Checkpoint,
                _ => return Err(anyhow!("Unknown blob kind: {}", kind)),
            };

            // Initialize lightweight network for publishing
            let data_dir = std::env::var("TACHYON_DATA_DIR").unwrap_or_else(|_| "./tachyon_data".to_string());
            std::fs::create_dir_all(&data_dir)?;
            let network = TachyonNetwork::new(Path::new(&data_dir)).await?;

            let (cid, ticket) = network
                .publish_blob_with_ticket(kind_enum, Bytes::from(bytes), height)
                .await?;

            println!("Published. CID={} Ticket={}", cid.to_hex(), ticket);
        }
    }

    Ok(())
}

/// Execute header sync commands
async fn execute_header_sync_command(command: HeaderSyncCommands) -> Result<()> {
    match command {
        HeaderSyncCommands::Bootstrap { data_dir, checkpoint_servers, min_sigs, trusted_pks } => {
            let mut cfg = HsConfig::default();
            cfg.network_config.data_dir = data_dir.clone();
            if let Some(list) = checkpoint_servers.as_deref() {
                cfg.network_config.checkpoint_servers = list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            cfg.security_config.min_checkpoint_signatures = min_sigs;
            if let Some(pks) = trusted_pks.as_deref() {
                let keys = pks.split(',')
                    .filter(|s| !s.trim().is_empty())
                    .filter_map(|hex_str| hex::decode(hex_str.trim_start_matches("0x")).ok())
                    .collect();
                cfg.security_config.trusted_checkpoint_keys = keys;
            }
            let mgr = HeaderSyncManager::new(cfg).await?;
            mgr.bootstrap_from_checkpoints().await?;
            let status = mgr.get_sync_status().await;
            println!("Bootstrapped to height {}", status.current_height);
        }
        HeaderSyncCommands::SyncOnce { data_dir, max_batch_size } => {
            let mut cfg = HsConfig::default();
            cfg.network_config.data_dir = data_dir.clone();
            cfg.sync_config.max_batch_size = max_batch_size;
            let mgr = HeaderSyncManager::new(cfg).await?;
            // Use observed latest height from announcements
            let latest = mgr.get_sync_status().await.tip_height;
            mgr.sync_to_height(latest).await?;
            let status = mgr.get_sync_status().await;
            println!("Synced to height {} (target {:?})", status.current_height, status.target_height);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test basic CLI parsing
        let cli = Cli::try_parse_from(&[
            "tachyon",
            "--verbose",
            "wallet",
            "info",
            "--db-path",
            "/tmp/test",
            "--password",
            "test",
        ]);
        assert!(cli.is_ok());

        // This is a basic test - full CLI testing would require more complex setup
    }
}
