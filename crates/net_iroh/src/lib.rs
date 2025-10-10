//! # net_iroh
//!
//! A wrapper over iroh + iroh-blobs for Tachyon network communication.
//! Provides high-level APIs for blob publishing, fetching, and control protocol handling.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{protocol::{AcceptError, ProtocolHandler, Router}, Endpoint, NodeId, Watcher};
use iroh_blobs::{store::fs::FsStore, Hash};
use iroh_blobs::{
    ticket::BlobTicket,
    BlobFormat,
};
use iroh_blobs::protocol::ChunkRangesExt;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
// Hardcoded configuration for simplicity and consistency
use futures::{Stream, StreamExt};
use std::pin::Pin;
// use tokio::io::AsyncReadExt; // not needed; RecvStream provides read_exact
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
};
use tracing::{debug, info};
use iroh::SecretKey;

// Integrity verification is provided by iroh-blobs via BLAKE3-verified streams.

/// Protocol identifiers for ALPN
pub const CONTROL_ALPN: &[u8] = b"tachyon/ctrl";
/// Hardcoded relay URL used in tickets and dialing
const DEFAULT_RELAY_URL: &str = "relay://localhost:4400";
/// Hardcoded 32-byte secret key for stable NodeId (example only; replace in production)
const SECRET_KEY_BYTES: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
    0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x01,
];

/// Blob content identifier (BLAKE3 hash)
pub type Cid = Hash;

/// Blob kind for announcements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlobKind {
    /// Commitment delta blob
    CommitmentDelta,
    /// Nullifier delta blob
    NullifierDelta,
    /// PCD transition blob
    PcdTransition,
    /// Header blob
    Header,
    /// Checkpoint blob
    Checkpoint,
}

/// Control message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Announce a new blob
    Announce {
        kind: BlobKind,
        cid: Cid,
        height: u64,
        size: usize,
        ticket: String,
    },
    /// Request a blob
    Request { cid: Cid },
    /// Response to a request
    Response {
        cid: Cid,
        data: Result<Bytes, String>,
    },
    /// Subscription request
    Subscribe { kinds: Vec<BlobKind> },
    /// Unsubscribe request
    Unsubscribe { kinds: Vec<BlobKind> },
    /// Request headers by consecutive height range
    GetHeadersByHeight { start: u64, count: u32 },
    /// Response with headers for a requested height range
    HeadersByHeight { start: u64, headers: Vec<Vec<u8>> },
}

/// Tachyon blob store wrapper around iroh-blobs
#[derive(Clone)]
pub struct TachyonBlobStore {
    /// File system store for persistent storage
    fs_store: Option<FsStore>,
    /// In-memory cache for frequently accessed blobs
    cache: Arc<RwLock<HashMap<Hash, Bytes>>>,
    /// Data directory path
    data_dir: PathBuf,
}

impl TachyonBlobStore {
    /// Create a new blob store
    pub async fn new(data_dir: &Path) -> Result<Self> {
        let mut store = Self {
            fs_store: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            data_dir: data_dir.to_path_buf(),
        };

        // Initialize the file system store
        store.initialize_fs_store().await?;

        Ok(store)
    }

    /// Initialize the underlying file system store
    async fn initialize_fs_store(&mut self) -> Result<()> {
        let store_path = self.data_dir.join("blobs");
        std::fs::create_dir_all(&store_path)?;

        // Use iroh-blobs FsStore for persistence
        let fs = FsStore::load(&store_path).await?;
        self.fs_store = Some(fs);

        Ok(())
    }

    /// Store a blob with the given content identifier
    pub async fn put(&self, hash: Hash, data: Bytes) -> Result<()> {
        // Persist to disk (via FsStore) and cache
        if let Some(fs) = &self.fs_store {
            // Store bytes, verify computed hash matches provided
            let tag_info = fs.add_bytes(data.clone()).await?;
            if tag_info.hash != hash {
                return Err(anyhow!(
                    "hash mismatch: provided {} computed {}",
                    hash.to_hex(),
                    tag_info.hash.to_hex()
                ));
            }
        }
        self.cache.write().unwrap().insert(hash, data);
        Ok(())
    }

    /// Retrieve a blob by its content identifier
    pub async fn get(&self, hash: &Hash) -> Result<Bytes> {
        // Check cache first
        if let Some(data) = self.cache.read().unwrap().get(hash) {
            return Ok(data.clone());
        }

        // Read from FsStore if available
        if let Some(fs) = &self.fs_store {
            let bytes = fs.get_bytes(*hash).await?;
            let data = Bytes::from(bytes);
            self.cache.write().unwrap().insert(*hash, data.clone());
            return Ok(data);
        }

        Err(anyhow!("Blob not found"))
    }

    /// Check if a blob exists
    pub async fn contains(&self, hash: &Hash) -> bool {
        if self.cache.read().unwrap().contains_key(hash) {
            return true;
        }
        if let Some(fs) = &self.fs_store {
            return fs.has(*hash).await.unwrap_or(false);
        }
        false
    }
}

fn default_relay_url() -> iroh::RelayUrl {
    DEFAULT_RELAY_URL.parse::<iroh::RelayUrl>().expect("invalid DEFAULT_RELAY_URL")
}

/// High-level network interface
pub struct TachyonNetwork {
    /// Iroh endpoint
    endpoint: Endpoint,
    /// Optional convenience local blob store (legacy, used in benches)
    pub blob_store: TachyonBlobStore,
    /// Control protocol handler
    _control_tx: mpsc::UnboundedSender<(NodeId, ControlMessage)>,
    /// Blob announcements
    announcements: broadcast::Sender<(BlobKind, Cid, u64, usize, String)>,
    /// Active control connections per peer
    peers: Arc<RwLock<HashMap<NodeId, Connection>>>,
    /// Background task handles
    _tasks: Vec<JoinHandle<()>>,
    /// Router handle for graceful shutdown
    router: Router,
    /// Recently published blobs (kind, bytes, height) for local consumers
    published: Arc<RwLock<Vec<(BlobKind, Vec<u8>, u64)>>>,
    /// Recent announcements (kind, cid, height, size, ticket) from peers and self
    recent_announcements: Arc<RwLock<Vec<(BlobKind, Cid, u64, usize, String)>>>,
}

/// Blob store trait for dependency injection
pub trait BlobStore: Send + Sync + 'static {
    fn put_blob<'a>(
        &'a self,
        cid: &Cid,
        data: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn fetch_blob<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Bytes>> + Send + 'a>>;
    fn has_blob<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

impl BlobStore for TachyonBlobStore {
    fn put_blob<'a>(
        &'a self,
        cid: &Cid,
        data: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.put(*cid, data))
    }

    fn fetch_blob<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Bytes>> + Send + 'a>> {
        Box::pin(self.get(cid))
    }

    fn has_blob<'a>(
        &'a self,
        cid: &'a Cid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(self.contains(cid))
    }
}

impl TachyonNetwork {
    /// Create a new TachyonNetwork instance
    pub async fn new(data_dir: &std::path::Path) -> Result<Self> {
        // Create iroh endpoint with hardcoded identity and always-on discovery
        let mut builder = Endpoint::builder();
        let secret_key = SecretKey::from_bytes(&SECRET_KEY_BYTES);
        builder = builder.secret_key(secret_key).discovery_n0();
        let endpoint = builder.bind().await?;

        // Create convenience local blob store for legacy callers/benches
        let blob_store = TachyonBlobStore::new(data_dir).await?;

        // Create channels for communication
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let (announcements, _) = broadcast::channel(1000);
        let announcements_tx = announcements.clone();
        let peers: Arc<RwLock<HashMap<NodeId, Connection>>> = Arc::new(RwLock::new(HashMap::new()));
        let recent_announcements: Arc<RwLock<Vec<(BlobKind, Cid, u64, usize, String)>>> = Arc::new(RwLock::new(Vec::new()));

        // Published blobs store for answering header requests
        let published: Arc<RwLock<Vec<(BlobKind, Vec<u8>, u64)>>> = Arc::new(RwLock::new(Vec::new()));

        // Control protocol handler registered with router
        let control_proto = ControlProtocol {
            peers: peers.clone(),
            control_tx: control_tx.clone(),
            published: published.clone(),
        };

        // Register control protocol and iroh-blobs provider for remote blob serving
        let mut router_builder = Router::builder(endpoint.clone())
            .accept(CONTROL_ALPN, control_proto.clone());

        // If we have an FsStore, wire up the blobs protocol handler so peers can fetch our blobs
        if let Some(fs) = blob_store.fs_store.as_ref() {
            let blobs = iroh_blobs::BlobsProtocol::new(fs, endpoint.clone(), None);
            router_builder = router_builder.accept(iroh_blobs::protocol::ALPN, blobs);
        }

        let router = router_builder.spawn();

        // Watch node address updates for observability
        let addr_task = {
            let ep = endpoint.clone();
            tokio::spawn(async move {
                let addr = ep.node_addr().initialized().await;
                info!("iroh node address initialized: {:?}", addr);
            })
        };

        // Handle incoming control messages
        let endpoint_clone = endpoint.clone();
        let peers_clone = peers.clone();
        let recent_announcements_clone = recent_announcements.clone();
        let control_task = tokio::spawn(async move {
            while let Some((node_id, message)) = control_rx.recv().await {
                // Record announce messages for later consumers
                if let ControlMessage::Announce { kind, cid, height, size, ticket } = &message {
                    let mut guard = recent_announcements_clone.write().unwrap();
                    guard.push((kind.clone(), *cid, *height, *size, ticket.clone()));
                    if guard.len() > 1000 {
                        let drain_len = guard.len() - 1000;
                        guard.drain(0..drain_len);
                    }
                }
                Self::handle_control_message(
                    node_id,
                    message,
                    &endpoint_clone,
                    &announcements_tx,
                    &peers_clone,
                )
                .await;
            }
        });

        Ok(TachyonNetwork {
            endpoint,
            blob_store,
            _control_tx: control_tx,
            announcements,
            peers,
            _tasks: vec![control_task, addr_task],
            router,
            published,
            recent_announcements,
        })
    }

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Publish a blob to the network
    pub async fn publish_blob(&self, kind: BlobKind, data: Bytes, height: u64) -> Result<Cid> {
        let (cid, _ticket) = self.publish_blob_with_ticket(kind, data, height).await?;
        Ok(cid)
    }

    /// Publish a blob and return both CID and a retrieval ticket string
    pub async fn publish_blob_with_ticket(
        &self,
        kind: BlobKind,
        data: Bytes,
        height: u64,
    ) -> Result<(Cid, String)> {
        // Add content to local blob store and generate a local ticket
        let hash = blake3::hash(&data);
        let cid = Cid::from(hash);
        self.blob_store.put(cid, data.clone()).await?;
        // Prefer a network ticket so remote clients can fetch via iroh-blobs
        // Fall back to local ticket format if node address is not initialized
        let ticket = {
            let mut node_addr = self.endpoint.node_addr().initialized().await;
            node_addr = node_addr.with_relay_url(default_relay_url());
            let blob_ticket = BlobTicket::new(node_addr, cid, BlobFormat::Raw);
            blob_ticket.to_string()
        };

        // Announce publication to control-plane peers
        let message = ControlMessage::Announce {
            kind: kind.clone(),
            cid,
            height,
            size: data.len(),
            ticket: ticket.clone(),
        };
        self.broadcast_control_message(message).await?;

        // Notify local subscribers
        let _ = self
            .announcements
            .send((kind.clone(), cid, height, data.len(), ticket.clone()));

        // Record locally for components that prefer direct access
        self.published
            .write()
            .unwrap()
            .push((kind.clone(), data.to_vec(), height));

        // Record in recent announcements as well
        {
            let mut guard = self.recent_announcements.write().unwrap();
            guard.push((kind.clone(), cid, height, data.len(), ticket.clone()));
            if guard.len() > 1000 {
                let drain_len = guard.len() - 1000;
                guard.drain(0..drain_len);
            }
        }

        info!("Published blob with ticket, CID {}", cid);
        Ok((cid, ticket))
    }

    /// Return the currently connected peer IDs
    pub fn peers_connected(&self) -> Vec<NodeId> {
        self.peers.read().unwrap().keys().cloned().collect()
    }

    /// Request headers by height range from a specific peer and wait for the response
    pub async fn request_headers_from_peer_by_height(
        &self,
        peer_id: NodeId,
        start: u64,
        count: u32,
    ) -> Result<Vec<Vec<u8>>> {
        let peers = self.peers.read().unwrap();
        let conn = peers
            .get(&peer_id)
            .ok_or_else(|| anyhow!("not connected to requested peer"))?
            .clone();
        drop(peers);

        let (mut send, recv) = conn.open_bi().await?;
        let req = ControlMessage::GetHeadersByHeight { start, count };
        let encoded = bincode::serialize(&req).map_err(|e| anyhow!(e))?;
        write_framed(&mut send, &encoded).await?;
        // Wait for a single response on this bi-stream
        let buf = read_framed(recv).await?;
        let resp: ControlMessage = bincode::deserialize(&buf).map_err(|e| anyhow!(e))?;
        match resp {
            ControlMessage::HeadersByHeight { start: _s, headers } => Ok(headers),
            other => Err(anyhow!(format!("unexpected response: {:?}", other))),
        }
    }

    /// Request headers by height range from any connected peer
    pub async fn request_headers_from_any_peer_by_height(
        &self,
        start: u64,
        count: u32,
    ) -> Result<Vec<Vec<u8>>> {
        let peers: Vec<NodeId> = self.peers_connected();
        if peers.is_empty() {
            return Err(anyhow!("no connected peers"));
        }
        // Try peers in order until one responds successfully
        for pid in peers {
            if let Ok(headers) = self.request_headers_from_peer_by_height(pid, start, count).await {
                if !headers.is_empty() {
                    return Ok(headers);
                }
            }
        }
        Ok(Vec::new())
    }

    /// Subscribe to blob announcements
    pub fn subscribe_announcements(
        &self,
    ) -> broadcast::Receiver<(BlobKind, Cid, u64, usize, String)> {
        self.announcements.subscribe()
    }

    /// Return a snapshot of recently published blobs (kind, bytes, height)
    pub async fn get_published(&self) -> Vec<(BlobKind, Vec<u8>, u64)> {
        self.published.read().unwrap().clone()
    }

    /// Get a snapshot of recent announcements (kind, cid, height, size, ticket)
    pub fn get_recent_announcements(&self) -> Vec<(BlobKind, Cid, u64, usize, String)> {
        self.recent_announcements.read().unwrap().clone()
    }

    /// Fetch a blob by CID
    pub async fn fetch_blob_from_ticket(&self, ticket: &str) -> Result<Bytes> {
        // Local ticket format: "local:<hex_cid>"
        if let Some(hex_str) = ticket.strip_prefix("local:") {
            let bytes = hex::decode(hex_str).map_err(|e| anyhow!(e))?;
            if bytes.len() != 32 {
                return Err(anyhow!("invalid CID length in ticket"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let cid = Hash::from_bytes(arr);
            return self.blob_store.get(&cid).await;
        }
        // Remote blob ticket via iroh-blobs
        if let Ok(blob_ticket) = BlobTicket::from_str(ticket) {
            let node_addr = blob_ticket.node_addr().clone();
            let conn = self
                .endpoint
                .connect(node_addr, iroh_blobs::protocol::ALPN)
                .await?;

            // Use our local FsStore downloader to fetch and store the blob
            let fs = self
                .blob_store
                .fs_store
                .as_ref()
                .ok_or_else(|| anyhow!("FsStore not initialized"))?;
            let remote = fs.remote();
            // Fetch entire content according to ticket format
            let content = blob_ticket.hash_and_format();
            remote
                .fetch(conn, content)
                .complete()
                .await
                .map_err(|e| anyhow!(e))?;
            // Return bytes from local store
            let data = fs.get_bytes(blob_ticket.hash()).await?;
            return Ok(Bytes::from(data));
        }
        Err(anyhow!("Unsupported ticket format"))
    }

    /// Fetch a byte range via ticket
    pub async fn fetch_range_from_ticket(
        &self,
        ticket: &str,
        range: std::ops::Range<u64>,
    ) -> Result<Bytes> {
        // Local ticket format: "local:<hex_cid>"
        if let Some(hex_str) = ticket.strip_prefix("local:") {
            let bytes = hex::decode(hex_str).map_err(|e| anyhow!(e))?;
            if bytes.len() != 32 {
                return Err(anyhow!("invalid CID length in ticket"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let cid = Hash::from_bytes(arr);
            // Serve from local FsStore using export_ranges
            let fs = self
                .blob_store
                .fs_store
                .as_ref()
                .ok_or_else(|| anyhow!("FsStore not initialized"))?;
            let data = fs
                .blobs()
                .export_ranges(cid, range.clone())
                .concatenate()
                .await
                .map_err(|e| anyhow!(e))?;
            return Ok(Bytes::from(data));
        }

        // Remote blob ticket via iroh-blobs
        if let Ok(blob_ticket) = BlobTicket::from_str(ticket) {
            // Guard: range fetch only supports Raw blobs
            if blob_ticket.format() != BlobFormat::Raw {
                return Err(anyhow!(
                    "range fetch only supported for Raw blobs (got {:?})",
                    blob_ticket.format()
                ));
            }
            let node_addr = blob_ticket.node_addr().clone();
            let conn = self
                .endpoint
                .connect(node_addr, iroh_blobs::protocol::ALPN)
                .await?;

            // Convert byte range to chunk ranges for verified streaming
            let chunk_ranges = ChunkRangesExt::bytes(range.clone());
            let request = iroh_blobs::protocol::GetRequest::blob_ranges(
                blob_ticket.hash(),
                chunk_ranges,
            );

            // Use our local FsStore to execute the remote get and store data
            let fs = self
                .blob_store
                .fs_store
                .as_ref()
                .ok_or_else(|| anyhow!("FsStore not initialized"))?;
            let remote = fs.remote();
            remote
                .execute_get(conn, request)
                .complete()
                .await
                .map_err(|e| anyhow!(e))?;

            // Read precisely the requested byte range from local store
            let out = fs
                .blobs()
                .export_ranges(blob_ticket.hash(), range.clone())
                .concatenate()
                .await
                .map_err(|e| anyhow!(e))?;
            return Ok(Bytes::from(out));
        }

        Err(anyhow!("Unsupported ticket format"))
    }

    /// Fetch a byte range via ticket as a streaming sequence of chunks.
    /// For remote tickets, this starts a background download task and streams
    /// verified bytes from the local store as they arrive, avoiding large allocations.
    pub async fn fetch_range_stream_from_ticket(
        &self,
        ticket: &str,
        range: std::ops::Range<u64>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>> {
        // Local ticket format: "local:<hex_cid>"
        if let Some(hex_str) = ticket.strip_prefix("local:") {
            let bytes = hex::decode(hex_str).map_err(|e| anyhow!(e))?;
            if bytes.len() != 32 {
                return Err(anyhow!("invalid CID length in ticket"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let cid = Hash::from_bytes(arr);
            // Serve from local FsStore using export_ranges as a byte stream
            let fs = self
                .blob_store
                .fs_store
                .as_ref()
                .ok_or_else(|| anyhow!("FsStore not initialized"))?;
            let stream = fs
                .blobs()
                .export_ranges(cid, range.clone())
                .stream()
                .filter_map(|item| async move {
                    match item {
                        iroh_blobs::api::proto::ExportRangesItem::Data(leaf) => Some(Ok(leaf.data)),
                        iroh_blobs::api::proto::ExportRangesItem::Error(e) => Some(Err(anyhow!(e))),
                        _ => None,
                    }
                });
            return Ok(Box::pin(stream));
        }

        // Remote blob ticket via iroh-blobs
        if let Ok(blob_ticket) = BlobTicket::from_str(ticket) {
            // Guard: range fetch only supports Raw blobs for now
            if blob_ticket.format() != BlobFormat::Raw {
                return Err(anyhow!(
                    "range fetch only supported for Raw blobs (got {:?})",
                    blob_ticket.format()
                ));
            }

            let node_addr = blob_ticket.node_addr().clone();
            let conn = self
                .endpoint
                .connect(node_addr, iroh_blobs::protocol::ALPN)
                .await?;

            // Convert byte range to chunk ranges for verified streaming
            let chunk_ranges = ChunkRangesExt::bytes(range.clone());
            let request = iroh_blobs::protocol::GetRequest::blob_ranges(
                blob_ticket.hash(),
                chunk_ranges,
            );

            // Use our local FsStore to execute the remote get in background,
            // while streaming from the local store as chunks arrive.
            let fs = self
                .blob_store
                .fs_store
                .as_ref()
                .ok_or_else(|| anyhow!("FsStore not initialized"))?;
            let remote = fs.remote();
            let progress = remote.execute_get(conn, request);
            // Start the fetch now; we won't wait for completion here.
            tokio::spawn(async move {
                let _ = progress.complete().await;
            });

            // Stream precisely the requested byte range from local store
            let stream = fs
                .blobs()
                .export_ranges(blob_ticket.hash(), range.clone())
                .stream()
                .filter_map(|item| async move {
                    match item {
                        iroh_blobs::api::proto::ExportRangesItem::Data(leaf) => Some(Ok(leaf.data)),
                        iroh_blobs::api::proto::ExportRangesItem::Error(e) => Some(Err(anyhow!(e))),
                        _ => None,
                    }
                });
            return Ok(Box::pin(stream));
        }

        Err(anyhow!("Unsupported ticket format"))
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_id: NodeId, peer_addr: Option<&iroh::RelayUrl>) -> Result<()> {
        let node_addr = if let Some(addr) = peer_addr {
            iroh::NodeAddr::new(peer_id).with_relay_url(addr.clone())
        } else {
            iroh::NodeAddr::new(peer_id).with_relay_url(default_relay_url())
        };

        let conn = self.endpoint.connect(node_addr, CONTROL_ALPN).await?;
        self.peers.write().unwrap().insert(peer_id, conn);
        Ok(())
    }

    /// Broadcast a control message to all connected peers
    async fn broadcast_control_message(&self, message: ControlMessage) -> Result<()> {
        let encoded = bincode::serialize(&message).map_err(|e| anyhow!(e))?;
        let peers = self.peers.read().unwrap().clone();
        for (peer_id, conn) in peers.into_iter() {
            match conn.open_bi().await {
                Ok((mut send, _recv)) => {
                    write_framed(&mut send, &encoded).await?;
                }
                Err(_err) => {
                    debug!("failed to open control stream to {}", peer_id);
                }
            }
        }
        Ok(())
    }

    /// Handle incoming control messages
    async fn handle_control_message(
        _node_id: NodeId,
        message: ControlMessage,
        _endpoint: &Endpoint,
        announcements: &broadcast::Sender<(BlobKind, Cid, u64, usize, String)>,
        _peers: &Arc<RwLock<HashMap<NodeId, Connection>>>,
    ) {
        match message {
            ControlMessage::Announce {
                kind,
                cid,
                height,
                size,
                ticket,
            } => {
                info!(
                    "Received announcement: {:?} CID {} at height {}",
                    kind, cid, height
                );
                let _ = announcements.send((kind, cid, height, size, ticket));
            }
            ControlMessage::Request { cid } => {
                debug!("Received blob request for CID {}", cid);
                // In local mode we don't serve remote requests yet
            }
            _ => {
                debug!("Received other control message: {:?}", message);
            }
        }
    }

    /// Gracefully shutdown the router and background tasks
    pub async fn shutdown(&self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}

// Simple length-prefixed framing helpers for control messages
async fn write_framed(send: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let len = bytes.len() as u32;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(bytes).await?;
    send.finish()?;
    Ok(())
}

async fn read_framed(mut recv: RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

// Control protocol that accepts control ALPN connections and forwards messages
#[derive(Clone, Debug)]
struct ControlProtocol {
    peers: Arc<RwLock<HashMap<NodeId, Connection>>>,
    control_tx: mpsc::UnboundedSender<(NodeId, ControlMessage)>,
    published: Arc<RwLock<Vec<(BlobKind, Vec<u8>, u64)>>>,
}

impl ProtocolHandler for ControlProtocol {
    fn accept(
        &self,
        conn: Connection,
    ) -> impl std::future::Future<Output = std::result::Result<(), AcceptError>> + Send {
        let peers = self.peers.clone();
        let tx = self.control_tx.clone();
        let published = self.published.clone();
        Box::pin(async move {
            let node_id = match conn.remote_node_id() {
                Ok(id) => id,
                Err(_) => return Ok(()),
            };
            peers.write().unwrap().insert(node_id, conn.clone());
            // handle incoming streams
            loop {
                match conn.accept_bi().await {
                    Ok((mut send, recv)) => {
                        let res = read_framed(recv).await;
                        match res.and_then(|buf| {
                            bincode::deserialize::<ControlMessage>(&buf).map_err(|e| anyhow!(e))
                        }) {
                            Ok(msg) => {
                                match msg {
                                    ControlMessage::GetHeadersByHeight { start, count } => {
                                        // Gather locally published Header blobs by height
                                        let mut headers: Vec<(u64, Vec<u8>)> = published
                                            .read()
                                            .unwrap()
                                            .iter()
                                            .filter(|(kind, _bytes, h)| *kind == BlobKind::Header && *h >= start)
                                            .map(|(_k, bytes, h)| (*h, bytes.clone()))
                                            .collect();
                                        headers.sort_by_key(|(h, _)| *h);
                                        let headers_bytes: Vec<Vec<u8>> = headers
                                            .into_iter()
                                            .take(count as usize)
                                            .map(|(_h, b)| b)
                                            .collect();
                                        let resp = ControlMessage::HeadersByHeight { start, headers: headers_bytes };
                                        if let Ok(encoded) = bincode::serialize(&resp) {
                                            let _ = write_framed(&mut send, &encoded).await;
                                        }
                                    }
                                    other => {
                                        // Forward other control messages to the control task
                                        let _ = tx.send((node_id, other));
                                    }
                                }
                            }
                            Err(_err) => {
                                // Failed to decode control message; drop the stream
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            peers.write().unwrap().remove(&node_id);
            Ok(())
        })
    }
}
