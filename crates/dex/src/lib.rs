//! dex
//!
//! In-memory orderbook engine and simple DEX service API.

use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::fs;
use std::path::Path;

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
#[derive(Default)]
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
        let mut bids: Vec<(Price, u64)> = self
            .bids
            .iter()
            .rev()
            .take(depth)
            .map(|(p, q)| (Price(*p), q.iter().map(|o| o.remaining.0).sum()))
            .collect();
        let mut asks: Vec<(Price, u64)> = self
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
        let bytes = bincode::serialize(&snapshot)?;
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
}

/// DEX facade over a pluggable engine
pub struct DexService { engine: Arc<dyn OrderBookEngine> }

impl DexService {
    pub fn new() -> Self { Self { engine: Arc::new(InMemoryEngine::new()) } }
    pub fn with_engine(engine: Arc<dyn OrderBookEngine>) -> Self { Self { engine } }
    pub fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> { self.engine.place_limit(owner, side, price, qty) }
    pub fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> { self.engine.place_market(owner, side, qty) }
    pub fn cancel(&self, id: OrderId) -> Result<bool> { self.engine.cancel(id) }
    pub fn orderbook(&self, depth: usize) -> OrderBookSnapshot { self.engine.snapshot(depth) }
    pub fn recent_trades(&self, limit: usize) -> Vec<Trade> { self.engine.recent_trades(limit) }
    pub fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) { self.engine.estimate_market_cost(side, qty) }
    pub fn get_order(&self, id: OrderId) -> Option<Order> { self.engine.get_order(id) }
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
}


