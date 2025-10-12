//! dex
//! Numan Thabit 2025
//! In-memory orderbook engine and DEX service API.

use anyhow::anyhow;
use crate::error::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::{fs, any::Any};
use std::path::{Path, PathBuf};

pub mod error {
    use thiserror::Error as ThisError;
    pub type Result<T> = core::result::Result<T, Error>;
    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("invalid input: {0}")] InvalidInput(String),
        #[error("io error: {0}")] Io(String),
        #[error("serialize error: {0}")] Serialize(String),
        #[error("deserialize error: {0}")] Deserialize(String),
        #[error("other: {0}")] Other(String),
    }
    impl From<anyhow::Error> for Error { fn from(e: anyhow::Error) -> Self { Error::Other(e.to_string()) } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side {
    Bid,
    Ask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrderId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnerId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price(pub u64); // price in quote per base (e.g., USDC per unit)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quantity(pub u64); // base units

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: OrderId,
    pub owner: OwnerId,
    pub side: Side,
    pub price: Price,
    pub quantity: Quantity,
    pub remaining: Quantity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub taker_id: OrderId,
    pub maker_id: OrderId,
    pub taker_owner: OwnerId,
    pub maker_owner: OwnerId,
    pub taker_side: Side,
    pub price: Price,
    pub quantity: Quantity,
}

/// Simple price-time priority orderbook using two maps of price levels.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct OrderBook {
    bids: BTreeMap<u64, VecDeque<Order>>, // key = price, max-best at end iterator via rev()
    asks: BTreeMap<u64, VecDeque<Order>>, // key = price, min-best at start iterator
    next_id: u64,
}

impl OrderBook {
    pub fn new() -> Self {
        Self { bids: BTreeMap::new(), asks: BTreeMap::new(), next_id: 1 }
    }

    fn alloc_id(&mut self) -> OrderId {
        let id = self.next_id;
        self.next_id += 1;
        OrderId(id)
    }

    pub fn best_bid(&self) -> Option<Price> {
        self.bids.keys().next_back().map(|p| Price(*p))
    }

    pub fn place_market(&mut self, owner: OwnerId, side: Side, qty: Quantity) -> (OrderId, Vec<Trade>) {
        let id = self.alloc_id();
        let mut remaining = qty.0;
        let mut trades = Vec::new();
        match side {
            Side::Bid => {
                let mut to_remove = Vec::new();
                // iterate asks from best up
                for (ask_price, level) in self.asks.iter_mut() {
                    if remaining == 0 { break; }
                    while let Some(mut maker) = level.front().cloned() {
                        if remaining == 0 { break; }
                        let trade_qty = remaining.min(maker.remaining.0);
                        if trade_qty == 0 { break; }
                        remaining -= trade_qty;
                        level.pop_front();
                        maker.remaining.0 -= trade_qty;
                        if maker.remaining.0 > 0 { level.push_front(maker.clone()); }
                        trades.push(Trade { taker_id: id, maker_id: maker.id, taker_owner: owner, maker_owner: maker.owner, taker_side: Side::Bid, price: Price(*ask_price), quantity: Quantity(trade_qty) });
                        if remaining == 0 { break; }
                    }
                    if level.is_empty() { to_remove.push(*ask_price); }
                    if remaining == 0 { break; }
                }
                for p in to_remove { self.asks.remove(&p); }
            }
            Side::Ask => {
                // iterate bids from best down
                let mut keys: Vec<u64> = self.bids.keys().cloned().collect();
                keys.sort_unstable_by(|a, b| b.cmp(a));
                let mut to_remove: Vec<u64> = Vec::new();
                for bid_price in keys {
                    if remaining == 0 { break; }
                    if let Some(level) = self.bids.get_mut(&bid_price) {
                        while let Some(mut maker) = level.front().cloned() {
                            if remaining == 0 { break; }
                            let trade_qty = remaining.min(maker.remaining.0);
                            if trade_qty == 0 { break; }
                            remaining -= trade_qty;
                            level.pop_front();
                            maker.remaining.0 -= trade_qty;
                            if maker.remaining.0 > 0 { level.push_front(maker.clone()); }
                            trades.push(Trade { taker_id: id, maker_id: maker.id, taker_owner: owner, maker_owner: maker.owner, taker_side: Side::Ask, price: Price(bid_price), quantity: Quantity(trade_qty) });
                            if remaining == 0 { break; }
                        }
                        if level.is_empty() { to_remove.push(bid_price); }
                    }
                }
                for p in to_remove { self.bids.remove(&p); }
            }
        }
        (id, trades)
    }

    pub fn best_ask(&self) -> Option<Price> {
        self.asks.keys().next().map(|p| Price(*p))
    }

    pub fn place_limit(&mut self, owner: OwnerId, side: Side, price: Price, qty: Quantity) -> (OrderId, Vec<Trade>) {
        let id = self.alloc_id();
        let mut incoming = Order { id, owner, side, price, quantity: qty, remaining: qty };
        let mut trades = Vec::new();

        match side {
            Side::Bid => {
                // Match against asks at prices <= bid price
                let mut to_remove = Vec::new();
                for (ask_price, level) in self.asks.iter_mut() {
                    if *ask_price > price.0 || incoming.remaining.0 == 0 {
                        break;
                    }
                    while let Some(mut maker) = level.front().cloned() {
                        if incoming.remaining.0 == 0 { break; }
                        let trade_qty = incoming.remaining.0.min(maker.remaining.0);
                        if trade_qty == 0 { break; }
                        incoming.remaining.0 -= trade_qty;
                        // Update maker remaining by popping and pushing back if any left
                        level.pop_front();
                        maker.remaining.0 -= trade_qty;
                        if maker.remaining.0 > 0 { level.push_front(maker.clone()); }
                        trades.push(Trade { taker_id: incoming.id, maker_id: maker.id, taker_owner: incoming.owner, maker_owner: maker.owner, taker_side: Side::Bid, price: Price(*ask_price), quantity: Quantity(trade_qty) });
                        if incoming.remaining.0 == 0 { break; }
                    }
                    if level.is_empty() { to_remove.push(*ask_price); }
                    if incoming.remaining.0 == 0 { break; }
                }
                for p in to_remove { self.asks.remove(&p); }
                if incoming.remaining.0 > 0 {
                    self.bids.entry(price.0).or_default().push_back(incoming);
                }
            }
            Side::Ask => {
                // Match against bids at prices >= ask price
                let mut to_remove = Vec::new();
                let mut iter_keys: Vec<u64> = self.bids.keys().cloned().collect();
                iter_keys.sort_unstable_by(|a, b| b.cmp(a)); // desc
                for bid_price in iter_keys {
                    if bid_price < price.0 || incoming.remaining.0 == 0 { break; }
                    if let Some(level) = self.bids.get_mut(&bid_price) {
                        while let Some(mut maker) = level.front().cloned() {
                            if incoming.remaining.0 == 0 { break; }
                            let trade_qty = incoming.remaining.0.min(maker.remaining.0);
                            if trade_qty == 0 { break; }
                            incoming.remaining.0 -= trade_qty;
                            level.pop_front();
                            maker.remaining.0 -= trade_qty;
                            if maker.remaining.0 > 0 { level.push_front(maker.clone()); }
                            trades.push(Trade { taker_id: incoming.id, maker_id: maker.id, taker_owner: incoming.owner, maker_owner: maker.owner, taker_side: Side::Ask, price: Price(bid_price), quantity: Quantity(trade_qty) });
                            if incoming.remaining.0 == 0 { break; }
                        }
                        if level.is_empty() { to_remove.push(bid_price); }
                    }
                    if incoming.remaining.0 == 0 { break; }
                }
                for p in to_remove { self.bids.remove(&p); }
                if incoming.remaining.0 > 0 {
                    self.asks.entry(price.0).or_default().push_back(incoming);
                }
            }
        }

        (id, trades)
    }

    pub fn cancel(&mut self, id: OrderId) -> bool {
        // Linear scan across price levels; acceptable for MVP.
        for (_p, level) in self.bids.iter_mut() {
            if let Some(pos) = level.iter().position(|o| o.id == id) {
                level.remove(pos);
                return true;
            }
        }
        for (_p, level) in self.asks.iter_mut() {
            if let Some(pos) = level.iter().position(|o| o.id == id) {
                level.remove(pos);
                return true;
            }
        }
        false
    }

    pub fn snapshot(&self, depth: usize) -> OrderBookSnapshot {
        let bids: Vec<(Price, u64)> = self
            .bids
            .iter()
            .rev()
            .take(depth)
            .map(|(p, q)| (Price(*p), q.iter().map(|o| o.remaining.0).sum()))
            .collect();
        let asks: Vec<(Price, u64)> = self
            .asks
            .iter()
            .take(depth)
            .map(|(p, q)| (Price(*p), q.iter().map(|o| o.remaining.0).sum()))
            .collect();
        // preserve order as best-to-worst for both sides
        OrderBookSnapshot { bids, asks }
    }

    pub fn find_order(&self, id: OrderId) -> Option<Order> {
        for (_p, level) in self.bids.iter() {
            if let Some(ord) = level.iter().find(|o| o.id == id) { return Some(ord.clone()); }
        }
        for (_p, level) in self.asks.iter() {
            if let Some(ord) = level.iter().find(|o| o.id == id) { return Some(ord.clone()); }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookSnapshot {
    pub bids: Vec<(Price, u64)>,
    pub asks: Vec<(Price, u64)>,
}

pub trait OrderBookEngine: Send + Sync {
    fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity) -> Result<(OrderId, Vec<Trade>)>;
    fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)>;
    fn cancel(&self, id: OrderId) -> Result<bool>;
    fn snapshot(&self, depth: usize) -> OrderBookSnapshot;
    fn recent_trades(&self, limit: usize) -> Vec<Trade>;
    fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64);
    fn get_order(&self, id: OrderId) -> Option<Order>;
    fn as_any(&self) -> &dyn Any;
}

/// In-memory engine implementing OrderBookEngine
pub struct InMemoryEngine {
    book: Arc<RwLock<OrderBook>>,
    trades: Arc<RwLock<VecDeque<Trade>>>,
    max_trades: usize,
}

impl InMemoryEngine {
    pub fn new() -> Self { Self { book: Arc::new(RwLock::new(OrderBook::new())), trades: Arc::new(RwLock::new(VecDeque::with_capacity(1024))), max_trades: 1024 } }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let book = self.book.read();
        let trades = self.trades.read();
        let snapshot = (&*book, &*trades);
        let bytes = bincode::serialize(&snapshot).map_err(|e| anyhow!("serialize snapshot: {}", e))?;
        if let Some(dir) = path.parent() { fs::create_dir_all(dir).ok(); }
        fs::write(path, bytes).map_err(|e| anyhow!("persist orderbook: {}", e))?;
        Ok(())
    }

    pub fn load_from_path(&self, path: &Path) -> Result<()> {
        if !path.exists() { return Ok(()); }
        let bytes = fs::read(path).map_err(|e| anyhow!("load orderbook: {}", e))?;
        if let Ok((book_ser, trades_ser)) = bincode::deserialize::<(OrderBook, VecDeque<Trade>)>(&bytes) {
            *self.book.write() = book_ser;
            *self.trades.write() = trades_ser;
        }
        Ok(())
    }
}

impl Default for InMemoryEngine {
    fn default() -> Self { Self::new() }
}

impl OrderBookEngine for InMemoryEngine {
    fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_limit(owner, side, price, qty);
        if !trades.is_empty() {
            let mut log = self.trades.write();
            for t in &trades {
                log.push_back(t.clone());
                if log.len() > self.max_trades { log.pop_front(); }
            }
        }
        Ok((id, trades))
    }
    fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_market(owner, side, qty);
        if !trades.is_empty() {
            let mut log = self.trades.write();
            for t in &trades {
                log.push_back(t.clone());
                if log.len() > self.max_trades { log.pop_front(); }
            }
        }
        Ok((id, trades))
    }
    fn cancel(&self, id: OrderId) -> Result<bool> {
        let mut book = self.book.write();
        Ok(book.cancel(id))
    }
    fn snapshot(&self, depth: usize) -> OrderBookSnapshot {
        let book = self.book.read();
        book.snapshot(depth)
    }
    fn recent_trades(&self, limit: usize) -> Vec<Trade> {
        let log = self.trades.read();
        let n = limit.min(log.len());
        log.iter().rev().take(n).cloned().collect()
    }
    fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) {
        // returns (filled_qty, quote_cost)
        let book = self.book.read();
        let mut remaining = qty.0;
        let mut filled = 0u64;
        let mut cost = 0u64;
        match side {
            Side::Bid => {
                for (p, level) in book.asks.iter() {
                    if remaining == 0 { break; }
                    let level_qty: u64 = level.iter().map(|o| o.remaining.0).sum();
                    let take = remaining.min(level_qty);
                    filled += take;
                    cost = cost.saturating_add(take.saturating_mul(*p));
                    remaining -= take;
                }
            }
            Side::Ask => {
                let mut keys: Vec<u64> = book.bids.keys().cloned().collect();
                keys.sort_unstable_by(|a, b| b.cmp(a));
                for p in keys {
                    if remaining == 0 { break; }
                    if let Some(level) = book.bids.get(&p) {
                        let level_qty: u64 = level.iter().map(|o| o.remaining.0).sum();
                        let take = remaining.min(level_qty);
                        filled += take;
                        cost = cost.saturating_add(take.saturating_mul(p));
                        remaining -= take;
                    }
                }
            }
        }
        (filled, cost)
    }
    fn get_order(&self, id: OrderId) -> Option<Order> { self.book.read().find_order(id) }
    fn as_any(&self) -> &dyn Any { self }
}

/// DEX facade over a pluggable engine
pub struct DexService {
    engine: Arc<dyn OrderBookEngine>,
    snapshot_path: Option<PathBuf>,
}

impl DexService {
    pub fn new() -> Self { Self { engine: Arc::new(InMemoryEngine::new()), snapshot_path: None } }
    pub fn with_engine(engine: Arc<dyn OrderBookEngine>) -> Self { Self { engine, snapshot_path: None } }
    /// Construct with an in-memory engine and enable snapshot persistence
    pub fn with_snapshot<P: AsRef<Path>>(snapshot_path: P) -> Self {
        let s = Self { engine: Arc::new(InMemoryEngine::new()), snapshot_path: Some(snapshot_path.as_ref().to_path_buf()) };
        if let Some(ref p) = s.snapshot_path { s.try_load_snapshot(p); }
        s
    }
    /// Construct with a provided engine and enable snapshot persistence (only used for InMemoryEngine)
    pub fn with_engine_and_snapshot<P: AsRef<Path>>(engine: Arc<dyn OrderBookEngine>, snapshot_path: P) -> Self {
        let s = Self { engine, snapshot_path: Some(snapshot_path.as_ref().to_path_buf()) };
        if let Some(ref p) = s.snapshot_path { s.try_load_snapshot(p); }
        s
    }
    fn try_load_snapshot(&self, path: &Path) {
        if let Some(engine) = self.engine.as_any().downcast_ref::<InMemoryEngine>() {
            let _ = engine.load_from_path(path);
        }
    }
    fn try_save_snapshot(&self) {
        if let (Some(path), Some(engine)) = (self.snapshot_path.as_ref(), self.engine.as_any().downcast_ref::<InMemoryEngine>()) {
            let _ = engine.save_to_path(path);
        }
    }
    pub fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        if price.0 == 0 { return Err(anyhow!("price must be > 0").into()); }
        if qty.0 == 0 { return Err(anyhow!("quantity must be > 0").into()); }
        let res = self.engine.place_limit(owner, side, price, qty);
        if res.is_ok() { self.try_save_snapshot(); }
        res
    }
    pub fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        if qty.0 == 0 { return Err(anyhow!("quantity must be > 0").into()); }
        let res = self.engine.place_market(owner, side, qty);
        if res.is_ok() { self.try_save_snapshot(); }
        res
    }
    pub fn cancel(&self, id: OrderId) -> Result<bool> {
        if id.0 == 0 { return Err(anyhow!("invalid order id").into()); }
        let res = self.engine.cancel(id);
        if res.as_ref().unwrap_or(&false) == &true { self.try_save_snapshot(); }
        res
    }
    pub fn orderbook(&self, depth: usize) -> OrderBookSnapshot { self.engine.snapshot(depth) }
    pub fn recent_trades(&self, limit: usize) -> Vec<Trade> { self.engine.recent_trades(limit) }
    pub fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) { self.engine.estimate_market_cost(side, qty) }
    pub fn get_order(&self, id: OrderId) -> Option<Order> { self.engine.get_order(id) }
}

impl Default for DexService {
    fn default() -> Self { Self::new() }
}

/// Sled-backed persistent engine implementing OrderBookEngine
pub struct SledEngine {
    db: sled::Db,
    book: Arc<RwLock<OrderBook>>,
    trades: Arc<RwLock<VecDeque<Trade>>>,
    max_trades: usize,
}

const SLED_KEY_BOOK: &str = "book";
const SLED_KEY_TRADES: &str = "trades";

impl SledEngine {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() { let _ = fs::create_dir_all(dir); }
        let db = sled::open(path).map_err(|e| anyhow!("sled open: {}", e))?;
        let book = if let Ok(Some(val)) = db.get(SLED_KEY_BOOK) {
            bincode::deserialize::<OrderBook>(&val).unwrap_or_else(|_| OrderBook::new())
        } else { OrderBook::new() };
        let trades = if let Ok(Some(val)) = db.get(SLED_KEY_TRADES) {
            bincode::deserialize::<VecDeque<Trade>>(&val).unwrap_or_else(|_| VecDeque::with_capacity(1024))
        } else { VecDeque::with_capacity(1024) };
        Ok(Self {
            db,
            book: Arc::new(RwLock::new(book)),
            trades: Arc::new(RwLock::new(trades)),
            max_trades: 1024,
        })
    }

    fn persist(&self) -> Result<()> {
        let book = self.book.read();
        let trades = self.trades.read();
        let book_bytes = bincode::serialize(&*book).map_err(|e| anyhow!("serialize book: {}", e))?;
        let trades_bytes = bincode::serialize(&*trades).map_err(|e| anyhow!("serialize trades: {}", e))?;
        self.db.insert(SLED_KEY_BOOK, book_bytes).map_err(|e| anyhow!("sled put book: {}", e))?;
        self.db.insert(SLED_KEY_TRADES, trades_bytes).map_err(|e| anyhow!("sled put trades: {}", e))?;
        self.db.flush().map_err(|e| anyhow!("sled flush: {}", e))?;
        Ok(())
    }
}

impl OrderBookEngine for SledEngine {
    fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_limit(owner, side, price, qty);
        if !trades.is_empty() {
            let mut log = self.trades.write();
            for t in &trades {
                log.push_back(t.clone());
                if log.len() > self.max_trades { log.pop_front(); }
            }
        }
        drop(book);
        self.persist()?;
        Ok((id, trades))
    }

    fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_market(owner, side, qty);
        if !trades.is_empty() {
            let mut log = self.trades.write();
            for t in &trades {
                log.push_back(t.clone());
                if log.len() > self.max_trades { log.pop_front(); }
            }
        }
        drop(book);
        self.persist()?;
        Ok((id, trades))
    }

    fn cancel(&self, id: OrderId) -> Result<bool> {
        let mut book = self.book.write();
        let ok = book.cancel(id);
        drop(book);
        self.persist()?;
        Ok(ok)
    }

    fn snapshot(&self, depth: usize) -> OrderBookSnapshot { self.book.read().snapshot(depth) }
    fn recent_trades(&self, limit: usize) -> Vec<Trade> {
        let log = self.trades.read();
        let n = limit.min(log.len());
        log.iter().rev().take(n).cloned().collect()
    }
    fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) {
        let book = self.book.read();
        // reuse same logic as InMemoryEngine by snapshotting
        let mut remaining = qty.0;
        let mut filled = 0u64;
        let mut cost = 0u64;
        match side {
            Side::Bid => {
                for (p, level) in book.asks.iter() {
                    if remaining == 0 { break; }
                    let level_qty: u64 = level.iter().map(|o| o.remaining.0).sum();
                    let take = remaining.min(level_qty);
                    filled += take;
                    cost = cost.saturating_add(take.saturating_mul(*p));
                    remaining -= take;
                }
            }
            Side::Ask => {
                let mut keys: Vec<u64> = book.bids.keys().cloned().collect();
                keys.sort_unstable_by(|a, b| b.cmp(a));
                for p in keys {
                    if remaining == 0 { break; }
                    if let Some(level) = book.bids.get(&p) {
                        let level_qty: u64 = level.iter().map(|o| o.remaining.0).sum();
                        let take = remaining.min(level_qty);
                        filled += take;
                        cost = cost.saturating_add(take.saturating_mul(p));
                        remaining -= take;
                    }
                }
            }
        }
        (filled, cost)
    }
    fn get_order(&self, id: OrderId) -> Option<Order> { self.book.read().find_order(id) }
    fn as_any(&self) -> &dyn Any { self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_match() {
        let dex = DexService::new();
        let (_b1, t0) = dex.place_limit(OwnerId(1), Side::Bid, Price(100), Quantity(10)).unwrap();
        assert!(t0.is_empty());
        let (_a1, t1) = dex.place_limit(OwnerId(2), Side::Ask, Price(90), Quantity(7)).unwrap();
        assert_eq!(t1.iter().map(|t| t.quantity.0).sum::<u64>(), 7);
        let snap = dex.orderbook(10);
        assert_eq!(snap.asks.iter().map(|x| x.1).sum::<u64>(), 0);
        assert_eq!(snap.bids.iter().map(|x| x.1).sum::<u64>(), 3);
        let (_id2, t2) = dex.place_limit(OwnerId(2), Side::Ask, Price(100), Quantity(3)).unwrap();
        assert_eq!(t2.iter().map(|t| t.quantity.0).sum::<u64>(), 3);
        let snap2 = dex.orderbook(10);
        assert_eq!(snap2.bids.iter().map(|x| x.1).sum::<u64>(), 0);
    }

    #[test]
    fn persists_across_reopen() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("dex_sled");

        // open persistent engine
        let engine = SledEngine::open(&db_path).unwrap();
        let dex = DexService::with_engine(Arc::new(engine));

        // place some orders
        let (_b1, _t0) = dex.place_limit(OwnerId(1), Side::Bid, Price(100), Quantity(5)).unwrap();
        let (_a1, _t1) = dex.place_limit(OwnerId(2), Side::Ask, Price(120), Quantity(3)).unwrap();

        // snapshot has both sides
        let snap = dex.orderbook(10);
        assert_eq!(snap.bids.iter().map(|x| x.1).sum::<u64>(), 5);
        assert_eq!(snap.asks.iter().map(|x| x.1).sum::<u64>(), 3);

        // reopen engine
        drop(dex);
        let engine2 = SledEngine::open(&db_path).unwrap();
        let dex2 = DexService::with_engine(Arc::new(engine2));

        // snapshot should be identical after reopen
        let snap2 = dex2.orderbook(10);
        assert_eq!(snap2.bids.iter().map(|x| x.1).sum::<u64>(), 5);
        assert_eq!(snap2.asks.iter().map(|x| x.1).sum::<u64>(), 3);
    }

    #[test]
    fn snapshot_persistence_inmemory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let snap_path = temp_dir.path().join("orderbook.bin");

        // Start with in-memory engine with snapshot
        let dex = DexService::with_snapshot(&snap_path);
        let (_b1, _t0) = dex.place_limit(OwnerId(1), Side::Bid, Price(150), Quantity(4)).unwrap();
        let (_a1, _t1) = dex.place_limit(OwnerId(2), Side::Ask, Price(200), Quantity(6)).unwrap();

        // Ensure snapshot file is created by an operation
        assert!(snap_path.exists());

        // Recreate service pointing to same snapshot path
        let dex2 = DexService::with_snapshot(&snap_path);
        let snap = dex2.orderbook(10);
        assert_eq!(snap.bids.iter().map(|x| x.1).sum::<u64>(), 4);
        assert_eq!(snap.asks.iter().map(|x| x.1).sum::<u64>(), 6);
    }
}


