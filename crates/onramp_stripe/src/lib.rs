//! onramp_stripe
//!
//! Minimal Stripe onramp integration façade for Tachyon.
//! - Provides a webhook server endpoint to receive onramp session updates.
//! - Maintains an in-memory queue of pending USDC topups keyed by session id.
//! - Exposes helpers to create a hosted onramp link (stubbed) and to claim a
//!   pending topup into a `wallet::TachyonWallet` by crediting USDC.

use anyhow::{anyhow, Result};
use axum::{http::HeaderMap, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;
use std::path::{Path, PathBuf};
use tokio::fs;

/// Public representation of a pending topup that can be claimed into a wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTopup {
    /// Stripe onramp session id or client reference id
    pub session_id: String,
    /// Amount of USDC base units to credit on successful claim
    pub usdc_amount: u64,
    /// Wallet database path hint for convenience (optional)
    pub target_db_path: Option<String>,
}

/// Minimal in-memory store for pending topups
#[derive(Default, Clone)]
pub struct PendingStore(Arc<RwLock<HashMap<String, PendingTopup>>>);

impl PendingStore {
    pub fn new() -> Self { Self::default() }
    pub async fn insert(&self, t: PendingTopup) { self.0.write().await.insert(t.session_id.clone(), t); }
    pub async fn remove(&self, id: &str) -> Option<PendingTopup> { self.0.write().await.remove(id) }
    pub async fn list(&self) -> Vec<PendingTopup> { self.0.read().await.values().cloned().collect() }
}

/// File-backed pending store that persists to a JSON file.
#[derive(Clone)]
pub struct FilePendingStore {
    inner: PendingStore,
    path: Arc<PathBuf>,
}

impl FilePendingStore {
    pub async fn new(path: &Path) -> Result<Self> {
        let store = Self { inner: PendingStore::new(), path: Arc::new(path.to_path_buf()) };
        store.load().await?;
        Ok(store)
    }

    async fn load(&self) -> Result<()> {
        if self.path.exists() {
            let data = fs::read(&*self.path).await?;
            let map: HashMap<String, PendingTopup> = serde_json::from_slice(&data)?;
            *self.inner.0.write().await = map;
        } else {
            if let Some(parent) = self.path.parent() { fs::create_dir_all(parent).await.ok(); }
            let empty = HashMap::<String, PendingTopup>::new();
            fs::write(&*self.path, serde_json::to_vec(&empty)?).await?;
        }
        Ok(())
    }

    async fn save(&self) -> Result<()> {
        let map = self.inner.0.read().await.clone();
        if let Some(parent) = self.path.parent() { fs::create_dir_all(parent).await.ok(); }
        fs::write(&*self.path, serde_json::to_vec_pretty(&map)?).await?;
        Ok(())
    }

    pub async fn insert(&self, t: PendingTopup) -> Result<()> { self.inner.insert(t).await; self.save().await }
    pub async fn remove(&self, id: &str) -> Result<Option<PendingTopup>> { let out = self.inner.remove(id).await; self.save().await.ok(); Ok(out) }
    pub async fn list(&self) -> Result<Vec<PendingTopup>> { Ok(self.inner.list().await) }
}

/// Webhook event payload subset we care about
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub r#type: String,
    pub data: serde_json::Value,
}

/// Configuration for hosted onramp/link creation
#[derive(Debug, Clone)]
pub struct OnrampConfig {
    /// Stripe secret/api key
    pub stripe_secret_key: String,
    /// Webhook secret for signature verification (optional for local dev)
    pub webhook_secret: Option<String>,
    /// Default destination chain address for USDC (opaque string for now)
    pub destination_address: String,
    /// Destination network (e.g., "ethereum", "solana", "polygon", "avalanche", "base", "stellar")
    pub destination_network: String,
    /// Destination currency (e.g., "usdc")
    pub destination_currency: String,
}

/// Result of creating an onramp session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnrampSession {
    pub session_id: String,
    pub url: String,
}

/// Create a hosted onramp link/session using Stripe API.
/// Returns the session id and URL users can open to complete purchase.
pub async fn create_onramp_session(cfg: &OnrampConfig, suggested_amount_minor: u64) -> Result<OnrampSession> {
    // NOTE: The Stripe Rust crate does not yet expose Onramp primitives.
    // The Onramp API is currently in public preview and uses a dedicated endpoint.
    // We'll use raw HTTPS request via reqwest with bearer auth for now.
    // Endpoint and fields may evolve; consult Stripe docs.

    #[derive(Serialize)]
    struct CreateSessionReq<'a> {
        destination_currency: &'a str,
        destination_network: &'a str,
        destination_address: &'a str,
        suggested_destination_amount: u64,
    }

    #[derive(Deserialize)]
    struct CreateSessionResp {
        id: String,
        client_secret: Option<String>,
        redirect_url: Option<String>,
    }

    let http = reqwest::Client::new();
    let req = CreateSessionReq {
        destination_currency: &cfg.destination_currency,
        destination_network: &cfg.destination_network,
        destination_address: &cfg.destination_address,
        suggested_destination_amount: suggested_amount_minor,
    };
    let resp = http
        .post("https://api.stripe.com/v1/crypto/onramp/sessions")
        .bearer_auth(cfg.stripe_secret_key.clone())
        .form(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("stripe session create failed: {}", resp.status()));
    }
    let body: CreateSessionResp = resp.json().await?;
    let url = body.redirect_url.or(body.client_secret).ok_or_else(|| anyhow!("stripe session missing redirect reference"))?;
    Ok(OnrampSession { session_id: body.id, url })
}

/// Fetch session details from Stripe and extract destination amount/currency/network.
pub async fn fetch_onramp_session_details(cfg: &OnrampConfig, session_id: &str) -> Result<(u64, String, String)> {
    #[derive(Deserialize)]
    struct SessionData {
        destination: Option<serde_json::Value>,
        amount_total: Option<u64>,
        currency: Option<String>,
        status: Option<String>,
    }

    let url = format!("https://api.stripe.com/v1/crypto/onramp/sessions/{}", session_id);
    let http = reqwest::Client::new();
    let resp = http.get(url).bearer_auth(cfg.stripe_secret_key.clone()).send().await?;
    if !resp.status().is_success() { return Err(anyhow!("failed to fetch session: {}", resp.status())); }
    let sess: SessionData = resp.json().await?;
    let status_ok = sess.status.as_deref().unwrap_or("") == "succeeded";
    if !status_ok { return Err(anyhow!("session not succeeded")); }
    // Prefer destination.amount and destination.currency; fall back to amount_total/currency
    let (amount, currency, network) = if let Some(dest) = &sess.destination {
        let amt = dest.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let cur = dest.get("currency").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let net = dest.get("network").and_then(|v| v.as_str()).unwrap_or("").to_string();
        (amt, cur, net)
    } else {
        (sess.amount_total.unwrap_or(0), sess.currency.unwrap_or_else(|| cfg.destination_currency.clone()), cfg.destination_network.clone())
    };
    if amount == 0 { return Err(anyhow!("session amount missing")); }
    Ok((amount, currency, network))
}

/// Start a simple webhook HTTP server to accept Stripe events.
/// This is a minimal server suitable for development; for production you may
/// want to run behind a reverse proxy and implement signature verification.
pub async fn start_webhook_server(addr: SocketAddr, store: FilePendingStore, webhook_secret: Option<String>, stripe_secret_key: Option<String>) -> Result<()> {
    let app = Router::new().route("/webhook/stripe", post({
        let store = store.clone();
        let webhook_secret = webhook_secret.clone();
        let stripe_secret_key = stripe_secret_key.clone();
        move |headers: HeaderMap, body: String| {
            let store = store.clone();
            async move {
                if let Err(e) = verify_and_handle_webhook(headers, &body, webhook_secret.clone(), stripe_secret_key.clone(), store.clone()).await {
                    tracing::warn!("webhook error: {}", e);
                    return Json(serde_json::json!({"status": "error"}));
                }
                Json(serde_json::json!({"status": "ok"}))
            }
        }
    }));

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| anyhow!("bind error: {}", e))?;
    info!("starting webhook server on {}", addr);
    axum::serve(listener, app).await.map_err(|e| anyhow!("server error: {}", e))
}

/// Verify signature (if secret provided), parse, and handle one webhook event.
async fn verify_and_handle_webhook(headers: HeaderMap, body: &str, webhook_secret: Option<String>, stripe_secret_key: Option<String>, store: FilePendingStore) -> Result<()> {
    if let Some(secret) = webhook_secret.as_ref() {
        verify_stripe_webhook_signature(headers.clone(), body, secret)?;
    }
    let event: serde_json::Value = serde_json::from_str(body)?;
    handle_stripe_event(event, stripe_secret_key, store).await;
    Ok(())
}

/// Handle Stripe event and enqueue pending USDC topups when appropriate.
async fn handle_stripe_event(event: serde_json::Value, stripe_secret_key: Option<String>, store: FilePendingStore) {
    let etype = event.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // The specific event names for Onramp are subject to change; these are typical patterns.
    if etype == "onramp.session.succeeded" || etype == "checkout.session.completed" {
        let session_id = event.get("data").and_then(|d| d.get("object")).and_then(|o| o.get("id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !session_id.is_empty() {
            // Confirm with Stripe for authoritative amount/currency
            if let Some(sk) = stripe_secret_key.as_ref() {
                let cfg = OnrampConfig { stripe_secret_key: sk.clone(), webhook_secret: None, destination_address: String::new(), destination_network: String::new(), destination_currency: String::new() };
                if let Ok((amount, currency, _network)) = fetch_onramp_session_details(&cfg, &session_id).await {
                    if currency.to_lowercase() == "usdc" {
                        let pending = PendingTopup { session_id: session_id.clone(), usdc_amount: amount, target_db_path: None };
                        let _ = store.insert(pending).await;
                        info!("queued pending topup: {} amount={} {}", session_id, amount, currency);
                    }
                }
            }
        }
    }
}

/// Verify Stripe webhook signature header using HMAC SHA256.
fn verify_stripe_webhook_signature(headers: HeaderMap, payload: &str, secret: &str) -> Result<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let sig_header = headers
        .get("Stripe-Signature")
        .ok_or_else(|| anyhow!("missing Stripe-Signature"))?
        .to_str()
        .map_err(|_| anyhow!("bad sig header"))?;

    // Header format: t=timestamp,v1=signature[,v1=signature2,...]
    let mut timestamp: Option<&str> = None;
    let mut signatures_hex: Vec<&str> = Vec::new();
    for part in sig_header.split(',') {
        let mut kv = part.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim();
        let v = kv.next().unwrap_or("").trim();
        match k {
            "t" => timestamp = Some(v),
            "v1" => signatures_hex.push(v),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or_else(|| anyhow!("invalid Stripe-Signature header: missing t"))?;
    if signatures_hex.is_empty() { return Err(anyhow!("invalid Stripe-Signature header: missing v1")); }

    // Enforce timestamp tolerance (5 minutes)
    let ts: i64 = timestamp.parse().map_err(|_| anyhow!("invalid signature timestamp"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if (now - ts).abs() > 300 { return Err(anyhow!("stale webhook signature")); }

    // Compute expected signature bytes
    let signed_payload = format!("{}.{}", timestamp, payload);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| anyhow!("hmac init failed"))?;
    mac.update(signed_payload.as_bytes());
    let expected_bytes = mac.finalize().into_bytes();

    // Compare against any provided v1 signature (hex) in constant time
    let mut any_match = false;
    for sig_hex in signatures_hex {
        if let Ok(provided_bytes) = hex::decode(sig_hex) {
            if constant_time_eq::constant_time_eq(&expected_bytes, &provided_bytes) {
                any_match = true;
                break;
            }
        }
    }
    if !any_match { return Err(anyhow!("invalid webhook signature")); }
    Ok(())
}

/// Claim a pending topup by session id and credit to the wallet's USDC balance.
pub async fn claim_pending_into_wallet(session_id: &str, store: &FilePendingStore, wallet: &wallet::TachyonWallet) -> Result<()> {
    if let Some(p) = store.remove(session_id).await? {
        wallet.deposit_usdc(p.usdc_amount).await
    } else {
        Err(anyhow!("pending topup not found"))
    }
}


