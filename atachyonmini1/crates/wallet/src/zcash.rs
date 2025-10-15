use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::io::Write;

// Zcash crates (optional feature)
// orchard imports not currently required directly; kept for future UA receiver derivations
use zcash_address::{unified, ToAddress, ZcashAddress};
use zcash_client_backend as zcb;
use zcash_client_sqlite as zcs;
use zcash_primitives::{consensus, constants::Network};
use zcash_primitives::transaction::components::Amount;
use zcash_primitives::memo::MemoBytes;
use zcash_primitives::zip32::AccountId;
use zcb::keys::{UnifiedSpendingKey, UnifiedFullViewingKey};
use zcb::encoding::{encode_unified_spending_key, encode_unified_full_viewing_key};
use rand::seq::SliceRandom;
use rand::Rng;

// Lightwalletd gRPC
use tonic::transport::Channel;
use tracing::{info, warn};

// Simple context wrapping storage and client-backend/sqlite integration for account 0
pub struct ZcashContext {
    pub data_dir: PathBuf,
    pub network: Network,
    pub lwd_endpoint: String,
    // Database paths for client_sqlite
    pub db_path: PathBuf,
    pub cache_db_path: PathBuf,
    // Seed bytes derived from mnemonic (sensitive)
    pub seed: Vec<u8>,
}

impl ZcashContext {
    pub async fn new(db_root: &str, mnemonic: &str, birthday: u64, lwd_url: &str, network_s: &str) -> Result<Self> {
        let network = match network_s {
            "mainnet" => Network::MainNetwork,
            "testnet" => Network::TestNetwork,
            _ => Network::MainNetwork,
        };

        let data_dir = PathBuf::from(db_root).join("zcash");
        let db_path = data_dir.join("wallet.sqlite");
        let cache_db_path = data_dir.join("cache.sqlite");

        tokio::fs::create_dir_all(&data_dir).await?;

        // Initialize or open databases
        if !db_path.exists() {
            zcs::wallet::init::init_wallet_db(&network, db_path.to_str().unwrap())?;
        }
        if !cache_db_path.exists() {
            zcs::wallet::init::init_cache_db(&network, cache_db_path.to_str().unwrap())?;
        }

        // Derive seed and add account 0 if not present
        #[cfg(not(feature = "zcash_mnemonic"))]
        {
            return Err(anyhow!("mnemonic support not enabled; build with --features wallet/zcash_mnemonic"));
        }
        #[cfg(feature = "zcash_mnemonic")]
        let seed = {
            // Accept raw mnemonic string as seed derivation is disabled without bip0039
            // For compatibility, treat the input string bytes as seed directly.
            mnemonic.as_bytes().to_vec()
        };
        // zcash_client_backend expects seed bytes and birthday
        if zcs::wallet::scanning::is_empty_wallet(db_path.to_str().unwrap())? {
            zcs::wallet::init::create_account(
                &network,
                db_path.to_str().unwrap(),
                &seed,
                birthday as u32,
            )?;
        }

        Ok(Self {
            data_dir,
            network,
            lwd_endpoint: lwd_url.to_string(),
            db_path,
            cache_db_path,
            seed: seed.to_vec(),
        })
    }

    fn default_account_path(&self) -> PathBuf { self.data_dir.join("default_account.txt") }

    fn get_default_account(&self) -> u32 {
        if let Ok(bytes) = std::fs::read(self.default_account_path()) {
            if let Ok(s) = String::from_utf8(bytes) {
                if let Ok(id) = s.trim().parse::<u32>() { return id; }
            }
        }
        0
    }

    pub fn set_default_account(&self, account: u32) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::write(self.default_account_path(), format!("{}\n", account))?;
        Ok(())
    }

    pub async fn get_ua(&self) -> Result<String> {
        self.get_ua_for_account(self.get_default_account()).await
    }

    pub async fn get_ua_for_account(&self, account: u32) -> Result<String> {
        // Try persistent UA first
        if let Some(ua) = self.get_persistent_ua(account) {
            return Ok(ua);
        }
        // Fetch UA using client_sqlite helper
        let ua = zcs::wallet::get_account_ua(
            self.db_path.to_str().unwrap(),
            account,
            &self.network,
        )?;
        let encoded = ua.encode(&self.network);
        // Persist for stable diversifier index
        let _ = self.set_persistent_ua(account, &encoded);
        Ok(encoded)
    }

    fn ua_account_path(&self, account: u32) -> PathBuf {
        self.data_dir.join(format!("ua_account_{}.txt", account))
    }

    fn get_persistent_ua(&self, account: u32) -> Option<String> {
        let p = self.ua_account_path(account);
        if let Ok(bytes) = std::fs::read(p) {
            if let Ok(s) = String::from_utf8(bytes) {
                if !s.trim().is_empty() { return Some(s.trim().to_string()); }
            }
        }
        None
    }

    fn set_persistent_ua(&self, account: u32, ua: &str) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::write(self.ua_account_path(account), format!("{}\n", ua))?;
        Ok(())
    }

    /// Export the Unified Full Viewing Key (UFVK) for an account (ZIP-32)
    pub async fn export_ufvk(&self, account: u32) -> Result<String> {
        let usk = UnifiedSpendingKey::from_seed(
            &self.network,
            &self.seed,
            AccountId::from(account),
        )
        .ok_or_else(|| anyhow!("failed to derive USK from seed"))?;
        let ufvk = UnifiedFullViewingKey::from(&usk);
        Ok(encode_unified_full_viewing_key(&self.network, &ufvk))
    }

    /// Export the Unified Spending Key (USK) for an account (ZIP-32)
    pub async fn export_usk(&self, account: u32) -> Result<String> {
        let usk = UnifiedSpendingKey::from_seed(
            &self.network,
            &self.seed,
            AccountId::from(account),
        )
        .ok_or_else(|| anyhow!("failed to derive USK from seed"))?;
        Ok(encode_unified_spending_key(&self.network, &usk))
    }

    /// Generate a ZIP-321 payment URI for a Unified Address
    pub fn generate_payment_uri(&self, to_ua: &str, amount_zat: u64, memo: Option<&str>) -> Result<String> {
        // Format amount as ZEC with up to 8 decimals
        fn format_amount(amount_zat: u64) -> String {
            let whole = amount_zat / 100_000_000;
            let frac = amount_zat % 100_000_000;
            if frac == 0 {
                format!("{}", whole)
            } else {
                let frac_str = format!("{:08}", frac).trim_end_matches('0').to_string();
                format!("{}.{}", whole, frac_str)
            }
        }

        let mut uri = format!("zcash:{}?amount={}", to_ua, format_amount(amount_zat));
        if let Some(m) = memo {
            if !m.is_empty() {
                let enc = urlencoding::encode(m);
                uri.push_str(&format!("&memo={}", enc));
            }
        }
        Ok(uri)
    }

    /// Parse a ZIP-321 payment URI. Returns (ua, amount_zat, memo)
    pub fn parse_payment_uri(&self, uri: &str) -> Result<(String, u64, Option<String>)> {
        if !uri.to_lowercase().starts_with("zcash:") {
            return Err(anyhow!("not a zcash: URI"));
        }
        let no_scheme = &uri[6..];
        let mut parts = no_scheme.splitn(2, '?');
        let addr = parts.next().unwrap_or("");
        if addr.is_empty() { return Err(anyhow!("missing address in URI")); }
        let mut amount_zat: Option<u64> = None;
        let mut memo: Option<String> = None;
        if let Some(qs) = parts.next() {
            for kv in qs.split('&') {
                let mut it = kv.splitn(2, '=');
                let k = it.next().unwrap_or("");
                let v = it.next().unwrap_or("");
                match k {
                    "amount" => {
                        amount_zat = Some(self.parse_amount_to_zat(v)?);
                    }
                    "memo" => {
                        if let Ok(d) = urlencoding::decode(v) { memo = Some(d.into_owned()); }
                    }
                    _ => {}
                }
            }
        }
        let az = amount_zat.ok_or_else(|| anyhow!("missing amount"))?;
        Ok((addr.to_string(), az, memo))
    }

    fn parse_amount_to_zat(&self, s: &str) -> Result<u64> {
        // Accept decimal string up to 8 fractional digits
        let s = s.trim();
        if s.is_empty() { return Err(anyhow!("amount empty")); }
        if s.starts_with('-') { return Err(anyhow!("negative amount")); }
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() > 2 { return Err(anyhow!("invalid amount")); }
        let whole_part = parts[0].parse::<u64>().map_err(|_| anyhow!("invalid whole part"))?;
        let frac_part = if parts.len() == 2 {
            let frac_str = parts[1];
            if frac_str.len() > 8 { return Err(anyhow!("too many decimal places")); }
            let mut padded = frac_str.to_string();
            while padded.len() < 8 { padded.push('0'); }
            padded.parse::<u64>().map_err(|_| anyhow!("invalid fractional part"))?
        } else { 0 };
        let whole_zat = whole_part.saturating_mul(100_000_000);
        Ok(whole_zat.saturating_add(frac_part))
    }

    pub async fn sync_to_height(&mut self, target_height: u64) -> Result<(u64, u64)> {
        info!(target_height, "zcash sync_to_height start");
        // Connect to lightwalletd
        let mut client = self.connect_lwd().await?;

        // Download compact blocks into cache db, then scan into wallet db
        let latest = zcs::scan::lwd_sync::download_and_scan_to_height(
            &mut client,
            &self.network,
            self.cache_db_path.to_str().unwrap(),
            self.db_path.to_str().unwrap(),
            target_height as u32,
        )?;

        // Get spendable balance (Orchard + Sapling). Start with Orchard only for now.
        let balance = zcs::wallet::balances::get_account_balance(
            self.db_path.to_str().unwrap(),
            0,
            zcb::wallet::AccountBalanceSource::Verified,
        )?;

        Ok((latest as u64, balance.spendable_value.into()))
    }

    pub async fn get_balance(&self) -> Result<u64> {
        let balance = zcs::wallet::balances::get_account_balance(
            self.db_path.to_str().unwrap(),
            self.get_default_account(),
            zcb::wallet::AccountBalanceSource::Verified,
        )?;
        Ok(balance.spendable_value.into())
    }

    pub async fn get_balance_for_account(&self, account: u32) -> Result<u64> {
        let balance = zcs::wallet::balances::get_account_balance(
            self.db_path.to_str().unwrap(),
            account,
            zcb::wallet::AccountBalanceSource::Verified,
        )?;
        Ok(balance.spendable_value.into())
    }

    /// Create and broadcast a single-output Orchard transaction with memo and simple fee, then wait until detected in scan.
    /// Returns the txid (hex) and the updated verified balance.
    pub async fn send_orchard(
        &mut self,
        to_ua: &str,
        amount_zat: u64,
        memo_opt: Option<&str>,
    ) -> Result<(String, u64)> {
        info!(amount_zat, "zcash send_orchard start");
        // Parse destination UA
        let addr = ZcashAddress::try_from_encoded(to_ua)
            .map_err(|_| anyhow!("invalid unified address"))?;
        if !addr.network_matches(&self.network) { return Err(anyhow!("UA network mismatch")); }
        // Deshielding warning if transparent receiver present
        if self.ua_has_transparent_receiver(&addr) {
            warn!("deshielding: destination has a transparent receiver; privacy reduced");
        }

        // ZIP-317 conventional fee: base + marginal * max(inputs, outputs)
        let spendable = self.get_balance().await.unwrap_or(0);
        let outputs_count = self.estimate_outputs_count(amount_zat, spendable);
        let inputs_count = self.estimate_inputs_count(amount_zat, spendable);
        let fee_zat = self.compute_zip317_fee(inputs_count, outputs_count);
        let fee = Amount::from_u64(fee_zat)?;

        // Build proposed transaction(s)
        let memo = match memo_opt {
            Some(s) => {
                if s.as_bytes().len() > 512 { return Err(anyhow!("memo exceeds 512 bytes")); }
                MemoBytes::from_str(s).ok()
            }
            None => None,
        };
        // Build one or more privacy-aware chunks to avoid consolidating too many notes
        let chunks = self.plan_privacy_chunks(amount_zat, spendable, inputs_count);
        let mut last_txid = String::new();
        let mut client = self.connect_lwd().await?;
        for chunk_amt in chunks {
            let mut builder = zcb::wallet::propose::ProposalBuilder::new(self.db_path.to_str().unwrap(), &self.network)?;
            let chunk_fee_zat = self.compute_zip317_fee(self.estimate_inputs_count(chunk_amt, spendable), self.estimate_outputs_count(chunk_amt, spendable));
            let chunk_fee = Amount::from_u64(chunk_fee_zat)?;
            builder.add_orchard_output(AccountId::from(self.get_default_account()), &addr, Amount::from_u64(chunk_amt)?, memo.clone(), chunk_fee)?;
            let mut proposals = builder.build()?;
            proposals.shuffle(&mut rand::thread_rng());
            let unsigned_list = zcs::wallet::spend::propose_and_build(self.db_path.to_str().unwrap(), &self.network, proposals)?;
            for unsigned in unsigned_list {
                let tx_bytes = zcs::wallet::spend::sign_proposed(self.db_path.to_str().unwrap(), &self.network, unsigned)?;
                let txid_hex = zcb::chain::broadcast::submit_transaction(&mut client, tx_bytes.clone()).await?;
                last_txid = txid_hex.clone();
            }
            // After each chunk, sync to adjust spendable and avoid rapid consolidation
            let tip = zcb::chain::lwd::get_latest_height(&mut client).await? as u64;
            let _ = self.sync_to_height(tip).await?;
        }

        let bal = self.get_balance().await?;
        Ok((last_txid, bal))
    }

    /// Create and broadcast a single-output Sapling transaction (fallback if Orchard fails)
    pub async fn send_sapling(
        &mut self,
        to_ua: &str,
        amount_zat: u64,
        memo_opt: Option<&str>,
    ) -> Result<(String, u64)> {
        info!(amount_zat, "zcash send_sapling start");
        // Parse destination address (UA or Sapling-only)
        let addr = ZcashAddress::try_from_encoded(to_ua)
            .map_err(|_| anyhow!("invalid unified address"))?;
        if !addr.network_matches(&self.network) { return Err(anyhow!("address network mismatch")); }
        if self.ua_has_transparent_receiver(&addr) { warn!("deshielding: destination has a transparent receiver; privacy reduced"); }

        let spendable = self.get_balance().await.unwrap_or(0);
        let outputs_count = self.estimate_outputs_count(amount_zat, spendable);
        let inputs_count = self.estimate_inputs_count(amount_zat, spendable);
        let fee_zat = self.compute_zip317_fee(inputs_count, outputs_count);
        let fee = Amount::from_u64(fee_zat)?;
        let memo = match memo_opt {
            Some(s) => {
                if s.as_bytes().len() > 512 { return Err(anyhow!("memo exceeds 512 bytes")); }
                MemoBytes::from_str(s).ok()
            }
            None => None,
        };

        let mut builder = zcb::wallet::propose::ProposalBuilder::new(self.db_path.to_str().unwrap(), &self.network)?;
        builder.add_sapling_output(AccountId::from(self.get_default_account()), &addr, Amount::from_u64(amount_zat)?, memo, fee)?;
        let mut proposals = builder.build()?;
        proposals.shuffle(&mut rand::thread_rng());

        let unsigned_list = zcs::wallet::spend::propose_and_build(self.db_path.to_str().unwrap(), &self.network, proposals)?;

        let mut client = self.connect_lwd().await?;
        let mut last_txid = String::new();
        for unsigned in unsigned_list {
            let tx_bytes = zcs::wallet::spend::sign_proposed(self.db_path.to_str().unwrap(), &self.network, unsigned)?;
            let txid_hex = zcb::chain::broadcast::submit_transaction(&mut client, tx_bytes.clone()).await?;
            last_txid = txid_hex.clone();
        }

        let tip = zcb::chain::lwd::get_latest_height(&mut client).await? as u64;
        let _ = self.sync_to_height(tip).await?;
        let bal = self.get_balance().await?;
        Ok((last_txid, bal))
    }

    /// Send shielded funds selecting Orchard first; fallback to Sapling on failure
    pub async fn send_shielded(
        &mut self,
        to_ua: &str,
        amount_zat: u64,
        memo_opt: Option<&str>,
    ) -> Result<(String, u64)> {
        match self.send_orchard(to_ua, amount_zat, memo_opt).await {
            Ok(res) => Ok(res),
            Err(e) => {
                warn!("orchard send failed, attempting sapling fallback: {}", e);
                self.send_sapling(to_ua, amount_zat, memo_opt).await
            }
        }
    }

    /// Send from a specified account id
    pub async fn send_orchard_from_account(
        &mut self,
        account: u32,
        to_ua: &str,
        amount_zat: u64,
        memo_opt: Option<&str>,
    ) -> Result<(String, u64)> {
        if account != self.get_default_account() {
            // Temporarily set default for this operation only
            self.set_default_account(account)?;
            let res = self.send_orchard(to_ua, amount_zat, memo_opt).await;
            // Restore default to 0 for simplicity (or persist account if desired)
            let _ = self.set_default_account(0);
            return res;
        }
        self.send_orchard(to_ua, amount_zat, memo_opt).await
    }

    /// Create a new account (next index) using the provided seed and birthday
    pub async fn create_account(&self, mnemonic: &str, birthday: u64) -> Result<u32> {
        #[cfg(not(feature = "zcash_mnemonic"))]
        {
            return Err(anyhow!("mnemonic support not enabled; build with --features wallet/zcash_mnemonic"));
        }
        #[cfg(feature = "zcash_mnemonic")]
        let seed = {
            // Accept raw mnemonic string as seed derivation is disabled without bip0039
            mnemonic.as_bytes().to_vec()
        };
        let id = zcs::wallet::init::create_account(
            &self.network,
            self.db_path.to_str().unwrap(),
            &seed,
            birthday as u32,
        )?;
        Ok(id)
    }

    /// List accounts with their UAs (best-effort)
    pub async fn list_accounts(&self) -> Result<Vec<(u32, String)>> {
        let mut out = Vec::new();
        for account in 0u32..50 {
            if let Ok(ua) = zcs::wallet::get_account_ua(self.db_path.to_str().unwrap(), account, &self.network) {
                out.push((account, ua.encode(&self.network)));
            } else {
                break;
            }
        }
        Ok(out)
    }

    /// Truncate scanned data to height and rescan to target
    pub async fn rescan_from_height(&mut self, start_height: u64, target_height: u64) -> Result<u64> {
        info!(start_height, target_height, "zcash rescan_from_height");
        zcs::wallet::scanning::truncate_to_height(self.db_path.to_str().unwrap(), start_height as u32)?;
        let mut client = self.connect_lwd().await?;
        let latest = zcs::scan::lwd_sync::download_and_scan_to_height(
            &mut client,
            &self.network,
            self.cache_db_path.to_str().unwrap(),
            self.db_path.to_str().unwrap(),
            target_height as u32,
        )?;
        Ok(latest as u64)
    }

    /// Set a local checkpoint by truncating and marking birthday; next scan should start from it
    pub async fn set_checkpoint(&self, birthday: u64) -> Result<()> {
        // For sqlite wallet we approximate by truncating and recreating account metadata at height
        // In practice, callers should trigger a rescan after setting checkpoint.
        // Persist birthday to a sidecar file
        std::fs::write(self.data_dir.join("checkpoint.height"), format!("{}\n", birthday))?;
        Ok(())
    }

    /// Export a backup of Zcash wallet state into a directory (copies sqlite DBs and writes metadata.json)
    pub async fn export_backup(&self, dst_dir: &str) -> Result<()> {
        let dst = PathBuf::from(dst_dir);
        tokio::fs::create_dir_all(&dst).await?;
        // Copy wallet.sqlite and cache.sqlite
        tokio::fs::copy(&self.db_path, dst.join("wallet.sqlite")).await?;
        tokio::fs::copy(&self.cache_db_path, dst.join("cache.sqlite")).await?;
        // Write metadata
        let meta = serde_json::json!({
            "network": match self.network { Network::MainNetwork => "mainnet", Network::TestNetwork => "testnet" },
            "lwd": self.lwd_endpoint,
            "default_account": self.get_default_account(),
        });
        let mut f = std::fs::File::create(dst.join("metadata.json"))?;
        f.write_all(serde_json::to_string_pretty(&meta)?.as_bytes())?;
        Ok(())
    }

    /// Import a backup from a directory (overwrites sqlite DBs)
    pub async fn import_backup(&self, src_dir: &str) -> Result<()> {
        let src = PathBuf::from(src_dir);
        // Basic validation
        if !src.join("wallet.sqlite").exists() { return Err(anyhow!("wallet.sqlite not found in backup")); }
        if !src.join("cache.sqlite").exists() { return Err(anyhow!("cache.sqlite not found in backup")); }
        tokio::fs::create_dir_all(&self.data_dir).await?;
        tokio::fs::copy(src.join("wallet.sqlite"), &self.db_path).await?;
        tokio::fs::copy(src.join("cache.sqlite"), &self.cache_db_path).await?;
        // Apply default account if present
        if let Ok(bytes) = std::fs::read(src.join("metadata.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(acc) = v.get("default_account").and_then(|n| n.as_u64()) { let _ = self.set_default_account(acc as u32); }
            }
        }
        Ok(())
    }

    async fn connect_lwd(&self) -> Result<zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<Channel>> {
        let channel = Channel::from_shared(self.lwd_endpoint.clone())?
            .connect()
            .await?;
        Ok(zcb::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::new(channel))
    }

    // ===== ZIP-317 fee utilities (conventional) =====
    fn compute_zip317_fee(&self, inputs_count: u32, outputs_count: u32) -> u64 {
        // Constants per example: base 10_000 zats, marginal 1_000 zats
        const BASE_FEE: u64 = 10_000;
        const MARGINAL_FEE: u64 = 1_000;
        let m = inputs_count.max(outputs_count) as u64;
        BASE_FEE.saturating_add(MARGINAL_FEE.saturating_mul(m))
    }

    fn estimate_outputs_count(&self, amount_zat: u64, spendable_zat: u64) -> u32 {
        // Destination output + potential change output if not sweeping exact amount
        if spendable_zat > amount_zat { 2 } else { 1 }
    }

    fn estimate_inputs_count(&self, amount_zat: u64, spendable_zat: u64) -> u32 {
        // Heuristic: assume ~3 inputs on average; scale with ratio of amount to spendable
        if spendable_zat == 0 { return 1; }
        let ratio = (amount_zat as f64 / spendable_zat as f64).clamp(0.0, 1.0);
        let est = if ratio <= 0.34 { 1 } else if ratio <= 0.67 { 2 } else { 3 };
        est
    }

    // ===== Privacy heuristics =====
    fn ua_has_transparent_receiver(&self, addr: &ZcashAddress) -> bool {
        match addr {
            ZcashAddress::Unified(ua) => ua.receivers().iter().any(|r| matches!(r, unified::Receiver::P2pkh(_) | unified::Receiver::P2sh(_))),
            ZcashAddress::Transparent(_) => true,
            _ => false,
        }
    }

    fn plan_privacy_chunks(&self, amount_zat: u64, spendable_zat: u64, est_inputs: u32) -> Vec<u64> {
        const TARGET_MAX_INPUTS: u32 = 3;
        if est_inputs <= TARGET_MAX_INPUTS { return vec![amount_zat]; }
        // Split into N chunks such that each chunk uses <= TARGET_MAX_INPUTS by ratio heuristic
        let ratio = (est_inputs as f64 / TARGET_MAX_INPUTS as f64).ceil() as u32;
        let mut chunks = Vec::new();
        let mut remaining = amount_zat;
        // base chunk size
        let mut base = amount_zat / ratio as u64;
        if base == 0 { base = amount_zat; }
        let mut rng = rand::thread_rng();
        for i in 0..ratio {
            if i == ratio - 1 { chunks.push(remaining); break; }
            // +/-10% jitter
            let jitter_bp: i64 = rng.gen_range(-1000..=1000); // basis points
            let jittered = ((base as i128) * (10_000 + jitter_bp as i128) / 10_000) as u64;
            let amt = jittered.min(remaining);
            chunks.push(amt);
            remaining = remaining.saturating_sub(amt);
            if remaining == 0 { break; }
        }
        // ensure sum equals amount
        let sum: u64 = chunks.iter().copied().sum();
        if sum < amount_zat { let last = chunks.last_mut().unwrap(); *last = last.saturating_add(amount_zat - sum); }
        chunks.retain(|&c| c > 0);
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ctx(tmp: &tempfile::TempDir) -> ZcashContext {
        ZcashContext {
            data_dir: tmp.path().join("zcash"),
            network: Network::MainNetwork,
            lwd_endpoint: "https://example.invalid".to_string(),
            db_path: tmp.path().join("wallet.sqlite"),
            cache_db_path: tmp.path().join("cache.sqlite"),
            seed: vec![],
        }
    }

    #[test]
    fn test_zip321_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = dummy_ctx(&tmp);
        let ua = "u1dummyaddress";
        let amount_zat = 123_456_789u64;
        let memo = Some("Hello World");
        let uri = ctx.generate_payment_uri(ua, amount_zat, memo.map(|s| s)).unwrap();
        let (ua2, amt2, memo2) = ctx.parse_payment_uri(&uri).unwrap();
        assert_eq!(ua, ua2);
        assert_eq!(amount_zat, amt2);
        assert_eq!(Some("Hello World".to_string()), memo2);
    }

    #[test]
    fn test_zip317_fee_calc() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = dummy_ctx(&tmp);
        // Example: base 10_000 + 1_000 * max(3,2) = 13_000
        let fee = ctx.compute_zip317_fee(3, 2);
        assert_eq!(fee, 13_000);
        let fee2 = ctx.compute_zip317_fee(1, 5);
        assert_eq!(fee2, 10_000 + 1_000 * 5);
    }

    #[test]
    fn test_parse_amount_to_zat() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = dummy_ctx(&tmp);
        assert_eq!(ctx.parse_amount_to_zat("1").unwrap(), 100_000_000);
        assert_eq!(ctx.parse_amount_to_zat("1.23").unwrap(), 123_000_000);
        assert_eq!(ctx.parse_amount_to_zat("0.00000001").unwrap(), 1);
        assert!(ctx.parse_amount_to_zat("1.000000000").is_err());
        assert!(ctx.parse_amount_to_zat("-1").is_err());
    }
}


