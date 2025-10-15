//! # cli
//! Numan Thabit 2025
//! Command-line interface for Tachyon wallet and network tools.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::Path;
use wallet::{TachyonWallet, WalletConfig};
use bytes::Bytes;
use tachyon_core::{BlobKind, TachyonNetwork, NodeId};
use std::str::FromStr;
use tachyon_core as core;
use tachyon_core::{NodeConfig, NetworkConfig};
use tachyon_core::{HeaderSyncConfig as HsConfig, HeaderSyncManager};
#[cfg(feature = "onramp")]
use onramp_stripe as onramp;
use tachyon_zk::{RecursionCore, compute_tachy_digest};
use pasta_curves::Fp as Fr;
use tachyon_zk::tachyon as tachyon_api;
use tachyon_zk::unified_block::{prove_poly_publisher, verify_poly_publisher};
use tachyon_zk::wallet_step::{prove_wallet_step, verify_wallet_step};

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
    #[arg(short, long, default_value = "~/.tachyon")] 
    pub data_dir: String,
    /// Output format (table or json)
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,
    /// Non-interactive mode (do not prompt)
    #[arg(long, default_value_t = false)]
    pub non_interactive: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat { Table, Json }

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        wallet_command: WalletCommands,
    },
    /// Zcash: Export backup to directory
    #[cfg(feature = "zcash")]
    ZcashExportBackup {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Destination directory
        #[arg(long)]
        dst: String,
    },
    /// Zcash: Export UFVK (ZIP-32)
    #[cfg(feature = "zcash")]
    ZcashUfvk {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Account id
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    /// Zcash: Export USK (ZIP-32)
    #[cfg(feature = "zcash")]
    ZcashUsk {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Account id
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    /// Zcash: Generate ZIP-321 payment URI
    #[cfg(feature = "zcash")]
    ZcashPayUri {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Destination Unified Address
        #[arg(long)]
        to: String,
        /// Amount (zatoshi)
        #[arg(long)]
        amount: u64,
        /// Optional memo
        #[arg(long)]
        memo: Option<String>,
    },
    /// Zcash: Parse ZIP-321 payment URI
    #[cfg(feature = "zcash")]
    ZcashParseUri {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// zcash: URI
        #[arg(long)]
        uri: String,
    },
    /// Zcash: Import backup from directory
    #[cfg(feature = "zcash")]
    ZcashImportBackup {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Source directory
        #[arg(long)]
        src: String,
    },
    /// Zcash: List accounts with UAs
    #[cfg(feature = "zcash")]
    ZcashAccounts {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Zcash: Set default account id
    #[cfg(feature = "zcash")]
    ZcashSetDefaultAccount {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Account id
        #[arg(long)]
        account: u32,
    },
    /// Zcash: Rescan from a height to target
    #[cfg(feature = "zcash")]
    ZcashRescan {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Start height
        #[arg(long)]
        start: u64,
        /// Target height
        #[arg(long)]
        target: u64,
    },
    /// Zcash: Set checkpoint height
    #[cfg(feature = "zcash")]
    ZcashCheckpoint {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Checkpoint height
        #[arg(long)]
        height: u64,
    },
    /// Simple DEX operations (in-memory)
    Dex {
        #[command(subcommand)]
        dex_command: DexCommands,
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
    /// Stripe onramp integration
    #[cfg(feature = "onramp")]
    Onramp {
        #[command(subcommand)]
        onramp_command: OnrampCommands,
    },
    /// Process sample Tachyactions: compute digests and aggregate O(1)
    ProcessActions {
        /// Number of actions to synthesize
        #[arg(long, default_value_t = 4)]
        count: usize,
        /// Optional fixed seed (unused placeholder for now)
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Build a Tachystamp from hex inputs quickly (no wallet required)
    TachyBuildStamp {
        /// Anchor height
        #[arg(long)]
        height: u64,
        /// MMR root (32-byte hex)
        #[arg(long)]
        mmr: String,
        /// Nullifier root (32-byte hex)
        #[arg(long)]
        nulls: String,
        /// Comma-separated tachygrams (each 32-byte hex)
        #[arg(long, default_value = "")]
        grams: String,
        /// Optional action pair: left and right gram hex; may repeat
        #[arg(long = "action", value_parser, num_args(0..), value_delimiter = ' ')]
        actions: Vec<String>,
    },
    /// Verify a Tachystamp JSON (stdin or file path) and print aggregated commitment
    TachyVerifyStamp {
        /// Path to tachystamp JSON (reads stdin if omitted)
        #[arg(long)]
        file: Option<String>,
    },
    /// Proving parameters (SRS) management
    Params {
        #[command(subcommand)]
        params_command: ParamsCommands,
    },
    /// Prove a small polynomial publisher instance (demo bounds MAX_DEG=8, MAX_ROOTS=8)
    PolyPublisherProve {
        /// Security parameter k (2^k)
        #[arg(long, default_value_t = 12)]
        k: u32,
        /// A_i (as u64)
        #[arg(long)]
        a_i: u64,
        /// P_i (as u64)
        #[arg(long)]
        p_i: u64,
        /// A_{i+1} (as u64)
        #[arg(long)]
        a_next: u64,
        /// h_i (as u64)
        #[arg(long)]
        h_i: u64,
        /// Coefficients c0,c1,... (comma-separated u64)
        #[arg(long)]
        coeffs: String,
        /// Roots list r0,r1,... (comma-separated u64)
        #[arg(long)]
        roots: String,
        /// Block length (<= roots.len())
        #[arg(long)]
        block_len: u64,
    },
    /// Verify a small polynomial publisher proof (demo bounds MAX_DEG=8, MAX_ROOTS=8)
    PolyPublisherVerify {
        /// Security parameter k (2^k)
        #[arg(long, default_value_t = 12)]
        k: u32,
        /// A_i (as u64)
        #[arg(long)]
        a_i: u64,
        /// P_i (as u64)
        #[arg(long)]
        p_i: u64,
        /// A_{i+1} (as u64)
        #[arg(long)]
        a_next: u64,
        /// h_i (as u64)
        #[arg(long)]
        h_i: u64,
        /// Block length
        #[arg(long)]
        block_len: u64,
        /// Proof hex string
        #[arg(long)]
        proof_hex: String,
    },
    /// Prove a wallet IVC step (demo bounds MAX_ROOTS=8)
    WalletStepProve {
        /// Security parameter k (2^k)
        #[arg(long, default_value_t = 12)]
        k: u32,
        /// A_i, S_i, P_i, A_{i+1}, S_{i+1} as u64 values (digest placeholders)
        #[arg(long)] a_i: u64,
        #[arg(long)] s_i: u64,
        #[arg(long)] p_i: u64,
        #[arg(long)] a_next: u64,
        #[arg(long)] s_next: u64,
        /// secret tag v
        #[arg(long)] v: u64,
        /// Roots list r0,r1,... (comma-separated u64)
        #[arg(long)] roots: String,
        /// Flags list b0,b1,... (comma-separated 0/1)
        #[arg(long)] flags: String,
        /// beta inverse witness (u64)
        #[arg(long)] beta: u64,
    },
    /// Verify a wallet IVC step (demo bounds MAX_ROOTS=8)
    WalletStepVerify {
        /// Security parameter k (2^k)
        #[arg(long, default_value_t = 12)]
        k: u32,
        /// A_i, S_i, P_i, A_{i+1}, S_{i+1} as u64 values
        #[arg(long)] a_i: u64,
        #[arg(long)] s_i: u64,
        #[arg(long)] p_i: u64,
        #[arg(long)] a_next: u64,
        #[arg(long)] s_next: u64,
        /// Proof hex
        #[arg(long)] proof_hex: String,
    },
}
#[derive(Subcommand)]
pub enum ParamsCommands {
    /// Generate a new SRS with specified k and write to file
    Gen {
        /// Output file path
        #[arg(long)]
        out: String,
        /// Security parameter k (circuit size = 2^k)
        #[arg(long, default_value_t = 12)]
        k: u32,
    },
    /// Inspect an existing SRS file
    Info {
        /// SRS file path
        #[arg(long)]
        file: String,
    },
}

/// Wallet-specific commands
#[derive(Subcommand)]
pub enum WalletCommands {
    /// Share a simple OOB recipient URI for a named wallet
    Share {
        /// Wallet name (under <data_dir>/wallets/<name>)
        #[arg(short, long)]
        name: String,

        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Send an out-of-band payment in one step
    ///
    /// Accepts either a full OOB URI (tachyon:oobpay?pk=0x...) or raw 0x<pk> for --to
    SendOob {
        /// Sender wallet name (under <data_dir>/wallets/<from>)
        #[arg(long)]
        from: String,

        /// Master password for sender wallet
        #[arg(short, long)]
        password: String,

        /// Recipient OOB URI (tachyon:oobpay?pk=0x...) or 0x<kyber-pk-hex>
        #[arg(long)]
        to: String,

        /// Amount/value to send
        #[arg(short, long)]
        value: u64,

        /// Optional memo
        #[arg(long)]
        memo: Option<String>,

        /// Optional Iroh peer NodeId (hex/base58 as supported by iroh) to send over network
        #[arg(long)]
        peer: Option<String>,
    },
    /// Claim an out-of-band payment from JSON blob
    ClaimOob {
        /// Receiver wallet name (under <data_dir>/wallets/<name>)
        #[arg(short, long)]
        name: String,

        /// Master password for receiver wallet
        #[arg(short, long)]
        password: String,

        /// Payment JSON (from the sender)
        #[arg(long)]
        json: String,
    },
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
    /// Zcash: Import seed and birthday height
    #[cfg(feature = "zcash")]
    ZcashImportSeed {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// BIP-39 mnemonic (quoted)
        #[arg(long)]
        mnemonic: String,
        /// Birthday height (mainnet)
        #[arg(long)]
        birthday: u64,
    },
    /// Zcash: Show Unified Address
    #[cfg(feature = "zcash")]
    ZcashUa {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Zcash: Sync to target height
    #[cfg(feature = "zcash")]
    ZcashSync {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Target height
        #[arg(long)]
        height: u64,
    },
    /// Zcash: Get verified balance
    #[cfg(feature = "zcash")]
    ZcashBalance {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
    },
    /// Zcash: Send Orchard TX
    #[cfg(feature = "zcash")]
    ZcashSend {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password
        #[arg(short, long)]
        password: String,
        /// Destination Unified Address
        #[arg(long)]
        to: String,
        /// Amount (zatoshi)
        #[arg(long)]
        amount: u64,
        /// Optional memo
        #[arg(long)]
        memo: Option<String>,
    },
}

/// Onramp commands
#[derive(Subcommand)]
pub enum OnrampCommands {
    /// Create onramp session and print URL
    CreateSession {
        /// Destination address for USDC
        #[arg(long)]
        destination: String,
        /// Destination network (ethereum|solana|polygon|avalanche|base|stellar)
        #[arg(long, default_value = "ethereum")]
        network: String,
        /// Destination currency (default: usdc)
        #[arg(long, default_value = "usdc")]
        currency: String,
        /// Suggested destination amount (USDC minor units, e.g., 1000000 = 1 USDC if 6 decimals)
        #[arg(long)]
        amount: u64,
    },
    /// Start local webhook server to receive Stripe events
    Webhook {
        /// Listen address, e.g., 0.0.0.0:8787
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// Path to persist pending topups JSON
        #[arg(long, default_value = "./onramp/pending.json")]
        pending_file: String,
        /// Webhook secret (or set STRIPE_WEBHOOK_SECRET)
        #[arg(long)]
        webhook_secret: Option<String>,
    },
    /// List pending topups
    Pending {
        /// Path to pending topups JSON
        #[arg(long, default_value = "./onramp/pending.json")]
        pending_file: String,
    },
    /// Claim a pending topup into a wallet
    Claim {
        /// Session id to claim
        #[arg(long)]
        session_id: String,
        /// Wallet database path
        #[arg(long)]
        db_path: String,
        /// Master password
        #[arg(long)]
        password: String,
        /// Path to pending topups JSON
        #[arg(long, default_value = "./onramp/pending.json")]
        pending_file: String,
    },
}

/// DEX commands
#[derive(Subcommand)]
pub enum DexCommands {
    /// Show balances (USDC/base)
    Balance {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Watch orderbook and trades (polling)
    Watch {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Poll interval millis
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        /// Depth levels
        #[arg(long, default_value_t = 10)]
        depth: usize,
    },
    /// Deposit USDC
    DepositUsdc {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Amount (USDC units)
        #[arg(short, long)]
        amount: u64,
    },
    /// Deposit base asset units (for selling)
    DepositBase {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Amount (base units)
        #[arg(short, long)]
        amount: u64,
    },
    /// Place a limit order
    PlaceLimit {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Side (bid/ask)
        #[arg(short, long)]
        side: String,
        /// Price (quote per base, e.g., USDC per unit)
        #[arg(short, long)]
        price: u64,
        /// Quantity (base units)
        #[arg(short, long)]
        qty: u64,
    },
    /// Place a market order
    PlaceMarket {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Side (bid/ask)
        #[arg(short, long)]
        side: String,
        /// Quantity (base units)
        #[arg(short, long)]
        qty: u64,
    },
    /// Cancel an order by id
    Cancel {
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Order ID
        #[arg(short, long)]
        id: u64,
    },
    /// Show orderbook snapshot
    OrderBook {
        /// Depth levels to show
        #[arg(short, long, default_value_t = 10)]
        depth: usize,
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Show recent trades
    Trades {
        /// Limit
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
        /// Wallet database path
        #[arg(short, long)]
        db_path: String,
        /// Master password (prompt if omitted)
        #[arg(short, long)]
        password: Option<String>,
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
    let mut cli = Cli::parse();

    // Expand ~ in data_dir
    if cli.data_dir.starts_with("~/") {
        if let Some(home) = dirs_next::home_dir() {
            let rest = &cli.data_dir[2..];
            cli.data_dir = format!("{}/{}", home.to_string_lossy(), rest);
        }
    }

    // Initialize simple logging (no env-filter/json features required)
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

    // Execute command
    match cli.command {
        Commands::Params { params_command } => execute_params_command(params_command).await,
        Commands::Wallet { wallet_command } => {
            execute_wallet_command(wallet_command, &cli.data_dir).await
        }
        #[cfg(feature = "zcash")]
        Commands::ZcashUfvk { db_path, password, account } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            // Allow insecure defaults for zcash tooling only in debug/test builds
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let ufvk = wallet.zcash_export_ufvk(account).await?;
            println!("{}", ufvk);
            Ok(())
        }
        #[cfg(feature = "zcash")]
        Commands::ZcashUsk { db_path, password, account } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let usk = wallet.zcash_export_usk(account).await?;
            println!("{}", usk);
            Ok(())
        }
        #[cfg(feature = "zcash")]
        Commands::ZcashPayUri { db_path, password, to, amount, memo } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let uri = wallet.zcash_generate_payment_uri(&to, amount, memo).await?;
            println!("{}", uri);
            Ok(())
        }
        #[cfg(feature = "zcash")]
        Commands::ZcashParseUri { db_path, password, uri } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let (ua, amount, memo) = wallet.zcash_parse_payment_uri(&uri).await?;
            let out = serde_json::json!({"ua": ua, "amount_zat": amount, "memo": memo});
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        Commands::Dex { dex_command } => execute_dex_command(dex_command, cli.format, cli.non_interactive).await,
        Commands::Network { network_command } => execute_network_command(network_command).await,
        Commands::HeaderSync { hs_command } => execute_header_sync_command(hs_command).await,
        Commands::Onramp { onramp_command } => execute_onramp_command(onramp_command).await,
        Commands::ProcessActions { count, seed } => {
            // Synthesize demo Tachyactions and aggregate their digests
            let mut digests: Vec<Fr> = Vec::with_capacity(count);
            // Simple deterministic sequence if seed provided; otherwise use OsRng-derived anchors
            let base_pk = Fr::from(123u64);
            let base_val = Fr::from(5u64);
            let mut cur_nonce = Fr::from(seed.unwrap_or(77));
            for i in 0..count {
                // Derive per-action values deterministically
                let pk = base_pk + Fr::from((i as u64) + 1);
                let val = base_val + Fr::from(((i as u64) % 11) + 1);
                cur_nonce += Fr::from(13u64);
                let d = compute_tachy_digest(pk, val, cur_nonce);
                digests.push(d);
            }

            // Aggregate digests using RecursionCore folding
            let core = RecursionCore::new()?;
            let (_proof, agg_bytes) = core.aggregate_tachy_digests(&digests)?;
            println!("final_agg_commitment=0x{}", hex::encode(agg_bytes));
            Ok(())
        }
        Commands::TachyBuildStamp { height, mmr, nulls, grams, actions } => {
            // Create builder
            let mut builder = tachyon_api::TachystampBuilder::new(height, &mmr, &nulls)?;
            builder = builder.add_grams_csv(&grams)?;
            // Parse actions as repeated triples: left,right[,sig]
            // Example: --action 0xAA.. 0xBB.. --action 0xCC.. 0xDD.. 0xSIG..
            let mut i = 0usize;
            while i < actions.len() {
                let left = actions.get(i).cloned().unwrap_or_default();
                let right = actions.get(i+1.min(actions.len().saturating_sub(1))).cloned().unwrap_or_default();
                let sig = actions.get(i+2).cloned();
                builder = builder.add_action_pair_hex(&left, &right, sig.as_deref())?;
                i += if sig.is_some() { 3 } else { 2 };
            }
            let stamp = builder.build()?;
            println!("{}", serde_json::to_string_pretty(&stamp)?);
            Ok(())
        }
        Commands::TachyVerifyStamp { file } => {
            let json = if let Some(path) = file { std::fs::read_to_string(path)? } else { use std::io::Read as _; let mut s = String::new(); std::io::stdin().read_to_string(&mut s)?; s };
            let stamp: tachyon_zk::tachyon::Tachystamp = serde_json::from_str(&json)?;
            // 1) Verify recursion proof against the aggregated commitment
            let core = RecursionCore::new()?;
            if stamp.aggregated_proof.is_empty() {
                // Allow empty proof only if the commitment is zero (represents no aggregation)
                if stamp.aggregated_commitment == [0u8; 32] {
                    println!("ok: empty recursion proof and zero commitment");
                } else {
                    println!("verification failed: empty recursion proof but non-zero commitment=0x{}", hex::encode(stamp.aggregated_commitment));
                    return Err(anyhow::anyhow!("recursion proof verification failed"));
                }
            } else {
                let verified = core.verify_aggregate_pair(&stamp.aggregated_proof, &stamp.aggregated_commitment)?;
                if !verified {
                    println!("verification failed: recursion proof invalid for commitment=0x{}", hex::encode(stamp.aggregated_commitment));
                    return Err(anyhow::anyhow!("recursion proof verification failed"));
                }
                println!("ok: recursion proof verified for agg=0x{}", hex::encode(stamp.aggregated_commitment));
            }

            // 2) Ease-of-use cross-check (builder path): re-aggregate action binding digests and compare commitments
            // Skip this check if there are no actions, since block-level stamps aggregate tx proofs instead.
            if !stamp.actions.is_empty() {
                let mut payloads: Vec<Vec<u8>> = Vec::new();
                for a in &stamp.actions { payloads.push(a.binding_digest.to_vec()); }
                let (_proof2, agg2) = core.aggregate_many_proofs(&payloads, tachyon_zk::tachyon::TACHY_FOLDING_FACTOR)?;
                if agg2 == stamp.aggregated_commitment {
                    println!("ok: action-binding aggregate matches stamp commitment");
                } else {
                    println!(
                        "warning: action-binding aggregate mismatch: expected=0x{} recomputed=0x{}",
                        hex::encode(stamp.aggregated_commitment),
                        hex::encode(agg2)
                    );
                }
            }

            Ok(())
        }
        Commands::PolyPublisherProve { k, a_i, p_i, a_next, h_i, coeffs, roots, block_len } => {
            const MAX_DEG: usize = 8; const MAX_ROOTS: usize = 8;
            let parse_u64s = |s: &str| -> Vec<u64> { s.split(',').filter(|x| !x.trim().is_empty()).filter_map(|x| x.trim().parse::<u64>().ok()).collect() };
            let coeff_vals = parse_u64s(&coeffs);
            let root_vals = parse_u64s(&roots);
            if coeff_vals.len() > MAX_DEG + 1 || root_vals.len() > MAX_ROOTS { return Err(anyhow!("exceeds demo bounds")); }
            let mut coeffs_fr = [Fr::ZERO; MAX_DEG + 1];
            for (i, v) in coeff_vals.iter().enumerate() { coeffs_fr[i] = Fr::from(*v); }
            let mut roots_fr = [Fr::ZERO; MAX_ROOTS];
            for (i, v) in root_vals.iter().enumerate() { roots_fr[i] = Fr::from(*v); }
            let mut flags = [false; MAX_ROOTS];
            for i in 0..(block_len as usize).min(root_vals.len()).min(MAX_ROOTS) { flags[i] = true; }
            let proof = prove_poly_publisher::<MAX_DEG, MAX_ROOTS>(k, Fr::from(a_i), Fr::from(p_i), Fr::from(a_next), Fr::from(h_i), block_len, coeffs_fr, roots_fr, flags)?;
            println!("0x{}", hex::encode(proof));
            Ok(())
        }
        Commands::PolyPublisherVerify { k, a_i, p_i, a_next, h_i, block_len, proof_hex } => {
            let proof = hex::decode(proof_hex.trim_start_matches("0x"))?;
            let ok = verify_poly_publisher(k, Fr::from(a_i), Fr::from(p_i), Fr::from(a_next), Fr::from(h_i), block_len, &proof)?;
            println!("{}", if ok { "ok" } else { "fail" });
            Ok(())
        }
        Commands::WalletStepProve { k, a_i, s_i, p_i, a_next, s_next, v, roots, flags, beta } => {
            const MAX_ROOTS: usize = 8;
            let parse_u64s = |s: &str| -> Vec<u64> { s.split(',').filter(|x| !x.trim().is_empty()).filter_map(|x| x.trim().parse::<u64>().ok()).collect() };
            let root_vals = parse_u64s(&roots);
            let flag_vals: Vec<u64> = parse_u64s(&flags);
            if root_vals.len() > MAX_ROOTS || flag_vals.len() > MAX_ROOTS { return Err(anyhow!("exceeds demo bounds")); }
            let mut roots_fr = [Fr::ZERO; MAX_ROOTS];
            for (i, val) in root_vals.iter().enumerate() { roots_fr[i] = Fr::from(*val); }
            let mut inc_flags = [false; MAX_ROOTS];
            for (i, val) in flag_vals.iter().enumerate() { inc_flags[i] = (*val != 0); }
            let proof = prove_wallet_step::<MAX_ROOTS>(k, Fr::from(a_i), Fr::from(s_i), Fr::from(p_i), Fr::from(a_next), Fr::from(s_next), Fr::from(v), roots_fr, inc_flags, Fr::from(beta))?;
            println!("0x{}", hex::encode(proof));
            Ok(())
        }
        Commands::WalletStepVerify { k, a_i, s_i, p_i, a_next, s_next, proof_hex } => {
            let proof = hex::decode(proof_hex.trim_start_matches("0x"))?;
            let ok = verify_wallet_step(k, Fr::from(a_i), Fr::from(s_i), Fr::from(p_i), Fr::from(a_next), Fr::from(s_next), &proof)?;
            println!("{}", if ok { "ok" } else { "fail" });
            Ok(())
        }
    }
}

/// Execute wallet commands
async fn execute_wallet_command(command: WalletCommands, data_dir: &str) -> Result<()> {
    match command {
        WalletCommands::Share { name, password } => {
            let db_path = format!("{}/wallets/{}", data_dir, name);
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let pk = wallet.get_oob_public_key().await;
            let uri = format!(
                "tachyon:oobpay?pk=0x{}&scheme=kyber768",
                hex::encode(pk.as_bytes())
            );
            println!("{}", uri);
        }
        WalletCommands::SendOob { from, password, to, value, memo, peer } => {
            let db_path = format!("{}/wallets/{}", data_dir, from);
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }

            // Build wallet
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;

            // Parse recipient pk from URI or hex
            let recipient_pk_bytes = if to.starts_with("tachyon:oobpay") {
                parse_oob_pk_hex_from_uri(&to)?.into_bytes()
            } else {
                to.trim_start_matches("0x").to_string().into_bytes()
            };
            let recipient_pk_raw = hex::decode(&recipient_pk_bytes)?;
            let recipient_pk = pq_crypto::KyberPublicKey::from_bytes(&recipient_pk_raw)?;

            // Compose note metadata
            let recipient_bytes = blake3::hash(recipient_pk.as_bytes());
            let mut h_commit = blake3::Hasher::new();
            h_commit.update(b"note_commitment:v1");
            h_commit.update(&value.to_le_bytes());
            h_commit.update(recipient_bytes.as_bytes());
            let commitment = h_commit.finalize();

            let mut h_rseed = blake3::Hasher::new();
            h_rseed.update(b"rseed:v1");
            h_rseed.update(commitment.as_bytes());
            let rseed = h_rseed.finalize();

            let memo_bytes = memo.unwrap_or_default().into_bytes();
            let mut meta = Vec::new();
            meta.extend_from_slice(commitment.as_bytes());
            meta.extend_from_slice(&value.to_le_bytes());
            meta.extend_from_slice(recipient_bytes.as_bytes());
            meta.extend_from_slice(rseed.as_bytes());
            meta.extend_from_slice(&(memo_bytes.len() as u16).to_le_bytes());
            meta.extend_from_slice(&memo_bytes);

            let payment = wallet
                .create_oob_payment(recipient_pk, meta, b"cli_payment".to_vec())
                .await?;

            if let Some(peer_str) = peer {
                // Attempt to parse NodeId via iroh API
                let parsed_node_id = match NodeId::from_str(&peer_str) {
                    Ok(id) => id,
                    Err(_) => {
                        println!("invalid peer NodeId");
                        return Ok(());
                    }
                };
                let hash = wallet.send_oob_over_iroh(parsed_node_id, payment).await?;
                println!("sent-oob-over-iroh: hash=0x{}", hex::encode(hash));
            } else {
                let json = serde_json::to_string(&payment)?;
                println!("{}", json);
            }
        }
        WalletCommands::ClaimOob { name, password, json } => {
            let db_path = format!("{}/wallets/{}", data_dir, name);
            let wallet_path = Path::new(&db_path);
            if !wallet_path.exists() {
                println!("Wallet not found at: {}", db_path);
                return Ok(());
            }
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            #[cfg(debug_assertions)]
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let payment: pq_crypto::OutOfBandPayment = serde_json::from_str(&json)?;
            let hash = wallet.receive_oob_payment(payment).await?;
            if let Some(note) = wallet.process_oob_payment(&hash).await? {
                println!("ok:value={}", note.value);
            } else {
                println!("no-note");
            }
        }
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
            #[cfg(debug_assertions)]
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
            #[cfg(debug_assertions)]
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
        #[cfg(feature = "zcash")]
        WalletCommands::ZcashImportSeed { db_path, password, mnemonic, birthday } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            wallet.zcash_import_seed(&mnemonic, birthday).await?;
            println!("ok");
        }
        #[cfg(feature = "zcash")]
        WalletCommands::ZcashUa { db_path, password } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let ua = wallet.zcash_get_unified_address().await?;
            println!("{}", ua);
        }
        #[cfg(feature = "zcash")]
        WalletCommands::ZcashSync { db_path, password, height } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let (scanned, bal) = wallet.zcash_sync_to_height(height).await?;
            println!("scanned_height={} balance_zat={}", scanned, bal);
        }
        #[cfg(feature = "zcash")]
        WalletCommands::ZcashBalance { db_path, password } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let bal = wallet.zcash_get_balance().await?;
            println!("{}", bal);
        }
        #[cfg(feature = "zcash")]
        WalletCommands::ZcashSend { db_path, password, to, amount, memo } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let mut wallet = TachyonWallet::new(cfg).await?;
            let (txid, bal) = wallet.zcash_send(&to, amount, memo).await?;
            println!("txid={} balance_zat={}", txid, bal);
        }
    }

    Ok(())
}

/// Execute DEX commands
fn prompt_password(non_interactive: bool) -> Result<String> {
    if non_interactive { return Err(anyhow!("password is required in non-interactive mode")); }
    let pw = rpassword::prompt_password("Password: ")?;
    Ok(pw)
}

async fn execute_dex_command(command: DexCommands, format: OutputFormat, non_interactive: bool) -> Result<()> {
    match command {
        DexCommands::Balance { db_path, password } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let (usdc, usdc_locked, base, base_locked) = wallet.get_balances().await?;
            match format {
                OutputFormat::Json => {
                    let out = serde_json::json!({"usdc": usdc, "usdc_locked": usdc_locked, "base": base, "base_locked": base_locked});
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
                OutputFormat::Table => {
                    println!("USDC: {} (locked {})", usdc, usdc_locked);
                    println!("BASE: {} (locked {})", base, base_locked);
                }
            }
        }
        DexCommands::DepositUsdc { db_path, password, amount } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            wallet.deposit_usdc(amount).await?;
            println!("Deposited {} USDC", amount);
        }
        DexCommands::DepositBase { db_path, password, amount } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            wallet.deposit_base(amount).await?;
            println!("Deposited {} BASE", amount);
        }
        DexCommands::PlaceLimit { db_path, password, side, price, qty } => {
            let s = match side.to_lowercase().as_str() { "bid" => dex::Side::Bid, "ask" => dex::Side::Ask, _ => return Err(anyhow!("invalid side")) };
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let (id, trades) = wallet.place_limit_order(s, price, qty).await?;
            println!("Order placed id={}", id.0);
            for t in trades {
                println!("Trade: side={:?} price={} qty={}", t.taker_side, t.price.0, t.quantity.0);
            }
        }
        DexCommands::PlaceMarket { db_path, password, side, qty } => {
            let s = match side.to_lowercase().as_str() { "bid" => dex::Side::Bid, "ask" => dex::Side::Ask, _ => return Err(anyhow!("invalid side")) };
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let (id, trades) = wallet.place_market_order(s, qty).await?;
            println!("Market order id={}", id.0);
            for t in trades { println!("Trade: side={:?} price={} qty={}", t.taker_side, t.price.0, t.quantity.0); }
        }
        DexCommands::Cancel { db_path, password, id } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let ok = wallet.cancel_order(dex::OrderId(id)).await?;
            println!("{}", if ok { "cancelled" } else { "not-found" });
        }
        DexCommands::OrderBook { depth, db_path, password } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let ob = wallet.orderbook(depth);
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({"bids": ob.bids.iter().map(|(p,q)| serde_json::json!({"price": p.0, "qty": q})).collect::<Vec<_>>(), "asks": ob.asks.iter().map(|(p,q)| serde_json::json!({"price": p.0, "qty": q})).collect::<Vec<_>>()}))?);
                }
                OutputFormat::Table => {
                    println!("Bids:");
                    for (p, q) in ob.bids { println!("  {} @ {}", q, p.0); }
                    println!("Asks:");
                    for (p, q) in ob.asks { println!("  {} @ {}", q, p.0); }
                }
            }
        }
        DexCommands::Trades { limit, db_path, password } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            let trades = wallet.trades(limit);
            match format {
                OutputFormat::Json => {
                    let rows: Vec<_> = trades.into_iter().map(|t| serde_json::json!({"side": format!("{:?}", t.taker_side).to_lowercase(), "price": t.price.0, "qty": t.quantity.0})).collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                OutputFormat::Table => {
                    for t in trades { println!("{:?}: qty={} price={}", t.taker_side, t.quantity.0, t.price.0); }
                }
            }
        }
        DexCommands::Watch { db_path, password, interval_ms, depth } => {
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.or_else(|| prompt_password(non_interactive).ok()).unwrap_or_default();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            loop {
                let ob = wallet.orderbook(depth);
                let trades = wallet.trades(10);
                match format {
                    OutputFormat::Json => {
                        let json = serde_json::json!({
                            "orderbook": {
                                "bids": ob.bids.iter().map(|(p,q)| serde_json::json!({"price": p.0, "qty": q})).collect::<Vec<_>>(),
                                "asks": ob.asks.iter().map(|(p,q)| serde_json::json!({"price": p.0, "qty": q})).collect::<Vec<_>>()
                            },
                            "trades": trades.iter().map(|t| serde_json::json!({"side": format!("{:?}", t.taker_side).to_lowercase(), "price": t.price.0, "qty": t.quantity.0})).collect::<Vec<_>>()
                        });
                        println!("{}", serde_json::to_string_pretty(&json)?);
                    }
                    OutputFormat::Table => {
                        println!("Bids:");
                        for (p,q) in &ob.bids { println!("  {} @ {}", q, p.0); }
                        println!("Asks:");
                        for (p,q) in &ob.asks { println!("  {} @ {}", q, p.0); }
                        println!("Recent trades:");
                        for t in trades { println!("{:?}: qty={} price={}", t.taker_side, t.quantity.0, t.price.0); }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
            }
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

/// Execute onramp commands
#[cfg(feature = "onramp")]
async fn execute_onramp_command(command: OnrampCommands) -> Result<()> {
    match command {
        OnrampCommands::CreateSession { destination, network, currency, amount } => {
            let key = std::env::var("STRIPE_SECRET_KEY").map_err(|_| anyhow!("missing STRIPE_SECRET_KEY"))?;
            let cfg = onramp::OnrampConfig { stripe_secret_key: key, webhook_secret: std::env::var("STRIPE_WEBHOOK_SECRET").ok(), destination_address: destination, destination_network: network, destination_currency: currency };
            let session = onramp::create_onramp_session(&cfg, amount).await?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"id": session.session_id, "url": session.url}))?);
        }
        OnrampCommands::Webhook { listen, pending_file, webhook_secret } => {
            let store = onramp::FilePendingStore::new(std::path::Path::new(&pending_file)).await?;
            let secret = webhook_secret.or_else(|| std::env::var("STRIPE_WEBHOOK_SECRET").ok());
            let stripe_sk = std::env::var("STRIPE_SECRET_KEY").ok();
            let addr: std::net::SocketAddr = listen.parse().map_err(|_| anyhow!("invalid listen addr"))?;
            onramp::start_webhook_server(addr, store.clone(), secret, stripe_sk).await?;
        }
        OnrampCommands::Pending { pending_file } => {
            let store = onramp::FilePendingStore::new(std::path::Path::new(&pending_file)).await?;
            let list = store.list().await?;
            println!("{}", serde_json::to_string_pretty(&list)?);
        }
        OnrampCommands::Claim { session_id, db_path, password, pending_file } => {
            let store = onramp::FilePendingStore::new(std::path::Path::new(&pending_file)).await?;
            let mut cfg = WalletConfig::from_env();
            cfg.db_path = db_path.clone();
            cfg.master_password = password.clone();
            std::env::set_var("TACHYON_ALLOW_INSECURE", "1");
            let wallet = TachyonWallet::new(cfg).await?;
            onramp::claim_pending_into_wallet(&session_id, &store, &wallet).await?;
            println!("ok");
        }
    }
    Ok(())
}

async fn execute_params_command(command: ParamsCommands) -> Result<()> {
    match command {
        ParamsCommands::Gen { out, k } => {
            // Generate IPA params for Pasta and write to file
            let params = halo2_proofs::ParamsIPA::<pasta_curves::vesta::Affine>::new(k);
            let mut f = std::fs::File::create(&out)?;
            params.write(&mut f)?;
            println!("ok: wrote SRS params (k={}) to {}", k, out);
        }
        ParamsCommands::Info { file } => {
            let mut f = std::fs::File::open(&file)?;
            let _params = halo2_proofs::ParamsIPA::<pasta_curves::vesta::Affine>::read(&mut f)?;
            println!("SRS: loaded from {} (size: {} bytes)", file, f.metadata()?.len());
        }
    }
    Ok(())
}

/// Extract the 0x<hex> Kyber public key from an OOB URI
fn parse_oob_pk_hex_from_uri(uri: &str) -> Result<String> {
    let lower = uri.to_lowercase();
    if !lower.starts_with("tachyon:oobpay") {
        return Err(anyhow::anyhow!("invalid oob uri"));
    }
    let parts: Vec<&str> = uri.split('?').collect();
    if parts.len() < 2 { return Err(anyhow::anyhow!("missing query")); }
    for kv in parts[1].split('&') {
        let mut it = kv.split('=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        if k == "pk" { return Ok(v.to_string()); }
    }
    Err(anyhow::anyhow!("pk not found in uri"))
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

            // Build node config without field reassigns after Default
            let net_cfg = NetworkConfig {
                data_dir: data_dir.clone(),
                bootstrap_nodes: bootstrap_list,
                listen_addr: Some(listen_addr.clone()),
            };

            let node_cfg = NodeConfig { network_config: net_cfg, ..Default::default() };

            // Start node
            let node = core::TachyonNode::new(node_cfg).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test basic CLI parsing
        let cli = Cli::try_parse_from([
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
