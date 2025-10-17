//! dex
//! Numan Thabit 2025
//! Production-ready in-memory orderbook engine and DEX service API.

use anyhow::anyhow;
use crate::error::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque, HashMap};
use std::sync::Arc;
use std::{fs, any::Any};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
        #[error("self trade prevented")] SelfTradePrevented,
        #[error("position limit exceeded")] PositionLimitExceeded,
        #[error("order size too large")] OrderSizeTooLarge,
        #[error("insufficient liquidity")] InsufficientLiquidity,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MarketId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price(pub u64); // price in quote per base (e.g., USDC per unit)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quantity(pub u64); // base units

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    Market,
    Limit,
    StopLoss,      // Triggers market order when price reaches stop
    StopLimit,     // Triggers limit order when price reaches stop
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeInForce {
    GTC, // Good til canceled
    IOC, // Immediate or cancel
    FOK, // Fill or kill
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: OrderId,
    pub owner: OwnerId,
    pub side: Side,
    pub order_type: OrderType,
    pub price: Price,
    pub quantity: Quantity,
    pub remaining: Quantity,
    pub time_in_force: TimeInForce,
    pub post_only: bool,
    pub stop_price: Option<Price>,
    pub status: OrderStatus,
    pub created_at: u64,
    pub updated_at: u64,
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
    pub maker_fee: u64,
    pub taker_fee: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candle {
    pub timestamp: u64,
    pub open: Price,
    pub high: Price,
    pub low: Price,
    pub close: Price,
    pub volume: u64,
    pub num_trades: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStats {
    pub last_price: Option<Price>,
    pub price_change_24h: i64,
    pub high_24h: Option<Price>,
    pub low_24h: Option<Price>,
    pub volume_24h: u64,
    pub num_trades_24h: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    pub maker_fee_bps: u64,  // basis points (1 bp = 0.01%)
    pub taker_fee_bps: u64,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            maker_fee_bps: 10,  // 0.1%
            taker_fee_bps: 20,  // 0.2%
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskLimits {
    pub max_order_size: u64,
    pub max_position_per_user: u64,
    pub prevent_self_trade: bool,
}

impl Default for RiskLimits {
    fn default() -> Self {
        Self {
            max_order_size: u64::MAX,
            max_position_per_user: u64::MAX,
            prevent_self_trade: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Market {
    pub id: MarketId,
    pub base_asset: String,
    pub quote_asset: String,
    pub price_decimals: u8,
    pub quantity_decimals: u8,
    pub min_order_size: u64,
}

fn timestamp_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Production-ready price-time priority orderbook with advanced features
#[derive(Clone, Serialize, Deserialize)]
pub struct OrderBook {
    bids: BTreeMap<u64, VecDeque<Order>>, // key = price, max-best at end iterator via rev()
    asks: BTreeMap<u64, VecDeque<Order>>, // key = price, min-best at start iterator
    stop_orders: Vec<Order>, // Stop orders waiting to be triggered
    order_index: HashMap<OrderId, Order>, // Fast lookup by order ID
    user_orders: HashMap<OwnerId, Vec<OrderId>>, // Orders by user
    user_positions: HashMap<OwnerId, i64>, // Net position per user (positive = long)
    next_id: u64,
    fee_config: FeeConfig,
    risk_limits: RiskLimits,
}

impl Default for OrderBook {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderBook {
    pub fn new() -> Self {
        Self::with_config(FeeConfig::default(), RiskLimits::default())
    }

    pub fn with_config(fee_config: FeeConfig, risk_limits: RiskLimits) -> Self {
        Self {
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            stop_orders: Vec::new(),
            order_index: HashMap::new(),
            user_orders: HashMap::new(),
            user_positions: HashMap::new(),
            next_id: 1,
            fee_config,
            risk_limits,
        }
    }

    fn alloc_id(&mut self) -> OrderId {
        let id = self.next_id;
        self.next_id += 1;
        OrderId(id)
    }

    #[allow(dead_code)]
    fn calc_fee(&self, quantity: u64, price: u64, is_maker: bool) -> u64 {
        let total = quantity.saturating_mul(price);
        let bps = if is_maker { self.fee_config.maker_fee_bps } else { self.fee_config.taker_fee_bps };
        total.saturating_mul(bps) / 10000
    }

    fn check_position_limit(&self, owner: OwnerId, side: Side, qty: u64) -> Result<()> {
        if self.risk_limits.max_position_per_user == u64::MAX {
            return Ok(());
        }
        let current = self.user_positions.get(&owner).copied().unwrap_or(0);
        let delta = qty as i64;
        let new_position = match side {
            Side::Bid => current + delta,
            Side::Ask => current - delta,
        };
        if new_position.unsigned_abs() > self.risk_limits.max_position_per_user {
            return Err(error::Error::PositionLimitExceeded);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn update_position(&mut self, owner: OwnerId, side: Side, qty: u64) {
        let delta = qty as i64;
        let entry = self.user_positions.entry(owner).or_insert(0);
        match side {
            Side::Bid => *entry += delta,
            Side::Ask => *entry -= delta,
        }
    }

    fn add_order_to_index(&mut self, order: Order) {
        let id = order.id;
        let owner = order.owner;
        self.order_index.insert(id, order.clone());
        self.user_orders.entry(owner).or_default().push(id);
    }

    fn remove_order_from_index(&mut self, id: OrderId) -> Option<Order> {
        if let Some(order) = self.order_index.remove(&id) {
            if let Some(user_orders) = self.user_orders.get_mut(&order.owner) {
                user_orders.retain(|&oid| oid != id);
            }
            Some(order)
        } else {
            None
        }
    }

    pub fn best_bid(&self) -> Option<Price> {
        self.bids.keys().next_back().map(|p| Price(*p))
    }

    pub fn best_ask(&self) -> Option<Price> {
        self.asks.keys().next().map(|p| Price(*p))
    }

    /// Place a market order (immediate execution at best available prices)
    pub fn place_market(&mut self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        if qty.0 > self.risk_limits.max_order_size {
            return Err(error::Error::OrderSizeTooLarge);
        }
        self.check_position_limit(owner, side, qty.0)?;
        
        let id = self.alloc_id();
        let mut remaining = qty.0;
        let mut trades = Vec::new();
        let now = timestamp_now();
        
        // Pre-calculate fees config to avoid borrowing issues
        let maker_fee_bps = self.fee_config.maker_fee_bps;
        let taker_fee_bps = self.fee_config.taker_fee_bps;
        let prevent_self_trade = self.risk_limits.prevent_self_trade;
        
        match side {
            Side::Bid => {
                let mut to_remove = Vec::new();
                for (ask_price, level) in self.asks.iter_mut() {
                    if remaining == 0 { break; }
                    while let Some(maker) = level.front().cloned() {
                        if remaining == 0 { break; }
                        if prevent_self_trade && maker.owner == owner {
                            level.pop_front();
                            level.push_back(maker);
                            break;
                        }
                        let trade_qty = remaining.min(maker.remaining.0);
                        if trade_qty == 0 { break; }
                        
                        let total = trade_qty.saturating_mul(*ask_price);
                        let maker_fee = total.saturating_mul(maker_fee_bps) / 10000;
                        let taker_fee = total.saturating_mul(taker_fee_bps) / 10000;
                        
                        remaining -= trade_qty;
                        level.pop_front();
                        
                        let mut maker_updated = maker.clone();
                        maker_updated.remaining.0 -= trade_qty;
                        maker_updated.updated_at = now;
                        maker_updated.status = if maker_updated.remaining.0 == 0 {
                            OrderStatus::Filled
                        } else {
                            OrderStatus::PartiallyFilled
                        };
                        
                        if maker_updated.remaining.0 > 0 {
                            level.push_front(maker_updated.clone());
                        }
                        self.order_index.insert(maker.id, maker_updated);
                        
                        // Track positions
                        *self.user_positions.entry(owner).or_insert(0) += trade_qty as i64;
                        *self.user_positions.entry(maker.owner).or_insert(0) -= trade_qty as i64;
                        
                        trades.push(Trade {
                            taker_id: id,
                            maker_id: maker.id,
                            taker_owner: owner,
                            maker_owner: maker.owner,
                            taker_side: Side::Bid,
                            price: Price(*ask_price),
                            quantity: Quantity(trade_qty),
                            maker_fee,
                            taker_fee,
                            timestamp: now,
                        });
                    }
                    if level.is_empty() { to_remove.push(*ask_price); }
                }
                for p in to_remove { self.asks.remove(&p); }
            }
            Side::Ask => {
                let mut keys: Vec<u64> = self.bids.keys().cloned().collect();
                keys.sort_unstable_by(|a, b| b.cmp(a));
                let mut to_remove: Vec<u64> = Vec::new();
                
                for bid_price in keys {
                    if remaining == 0 { break; }
                    if let Some(level) = self.bids.get_mut(&bid_price) {
                        while let Some(maker) = level.front().cloned() {
                            if remaining == 0 { break; }
                            if prevent_self_trade && maker.owner == owner {
                                level.pop_front();
                                level.push_back(maker);
                                break;
                            }
                            let trade_qty = remaining.min(maker.remaining.0);
                            if trade_qty == 0 { break; }
                            
                            let total = trade_qty.saturating_mul(bid_price);
                            let maker_fee = total.saturating_mul(maker_fee_bps) / 10000;
                            let taker_fee = total.saturating_mul(taker_fee_bps) / 10000;
                            
                            remaining -= trade_qty;
                            level.pop_front();
                            
                            let mut maker_updated = maker.clone();
                            maker_updated.remaining.0 -= trade_qty;
                            maker_updated.updated_at = now;
                            maker_updated.status = if maker_updated.remaining.0 == 0 {
                                OrderStatus::Filled
                            } else {
                                OrderStatus::PartiallyFilled
                            };
                            
                            if maker_updated.remaining.0 > 0 {
                                level.push_front(maker_updated.clone());
                            }
                            self.order_index.insert(maker.id, maker_updated);
                            
                            // Track positions
                            *self.user_positions.entry(owner).or_insert(0) -= trade_qty as i64;
                            *self.user_positions.entry(maker.owner).or_insert(0) += trade_qty as i64;
                            
                            trades.push(Trade {
                                taker_id: id,
                                maker_id: maker.id,
                                taker_owner: owner,
                                maker_owner: maker.owner,
                                taker_side: Side::Ask,
                                price: Price(bid_price),
                                quantity: Quantity(trade_qty),
                                maker_fee,
                                taker_fee,
                                timestamp: now,
                            });
                        }
                        if level.is_empty() { to_remove.push(bid_price); }
                    }
                }
                for p in to_remove { self.bids.remove(&p); }
            }
        }
        
        // Check stop orders that may have been triggered
        self.check_stop_orders();
        
        Ok((id, trades))
    }

    /// Place a limit order with advanced options (TIF, post-only, etc.)
    pub fn place_limit(&mut self, owner: OwnerId, side: Side, price: Price, qty: Quantity, 
                       time_in_force: TimeInForce, post_only: bool) -> Result<(OrderId, Vec<Trade>)> {
        if qty.0 > self.risk_limits.max_order_size {
            return Err(error::Error::OrderSizeTooLarge);
        }
        self.check_position_limit(owner, side, qty.0)?;
        let id = self.alloc_id();
        let now = timestamp_now();
        let mut incoming = Order {
            id,
            owner,
            side,
            order_type: OrderType::Limit,
            price,
            quantity: qty,
            remaining: qty,
            time_in_force,
            post_only,
            stop_price: None,
            status: OrderStatus::Open,
            created_at: now,
            updated_at: now,
        };
        let mut trades = Vec::new();
        
        // Post-only orders should not match immediately
        let should_match = !post_only;
        let original_qty = incoming.remaining.0;
        
        // Pre-calculate fees config to avoid borrowing issues
        let maker_fee_bps = self.fee_config.maker_fee_bps;
        let taker_fee_bps = self.fee_config.taker_fee_bps;
        let prevent_self_trade = self.risk_limits.prevent_self_trade;

        if should_match {
            match side {
                Side::Bid => {
                    let mut to_remove = Vec::new();
                    for (ask_price, level) in self.asks.iter_mut() {
                        if *ask_price > price.0 || incoming.remaining.0 == 0 {
                            break;
                        }
                        while let Some(maker) = level.front().cloned() {
                            if incoming.remaining.0 == 0 { break; }
                            if prevent_self_trade && maker.owner == owner {
                                return Err(error::Error::SelfTradePrevented);
                            }
                            let trade_qty = incoming.remaining.0.min(maker.remaining.0);
                            if trade_qty == 0 { break; }
                            
                            let total = trade_qty.saturating_mul(*ask_price);
                            let maker_fee = total.saturating_mul(maker_fee_bps) / 10000;
                            let taker_fee = total.saturating_mul(taker_fee_bps) / 10000;
                            
                            incoming.remaining.0 -= trade_qty;
                            level.pop_front();
                            
                            let mut maker_updated = maker.clone();
                            maker_updated.remaining.0 -= trade_qty;
                            maker_updated.updated_at = now;
                            maker_updated.status = if maker_updated.remaining.0 == 0 {
                                OrderStatus::Filled
                            } else {
                                OrderStatus::PartiallyFilled
                            };
                            
                            if maker_updated.remaining.0 > 0 {
                                level.push_front(maker_updated.clone());
                            }
                            self.order_index.insert(maker.id, maker_updated);
                            
                            // Track positions
                            *self.user_positions.entry(owner).or_insert(0) += trade_qty as i64;
                            *self.user_positions.entry(maker.owner).or_insert(0) -= trade_qty as i64;
                            
                            trades.push(Trade {
                                taker_id: incoming.id,
                                maker_id: maker.id,
                                taker_owner: incoming.owner,
                                maker_owner: maker.owner,
                                taker_side: Side::Bid,
                                price: Price(*ask_price),
                                quantity: Quantity(trade_qty),
                                maker_fee,
                                taker_fee,
                                timestamp: now,
                            });
                        }
                        if level.is_empty() { to_remove.push(*ask_price); }
                        if incoming.remaining.0 == 0 { break; }
                    }
                    for p in to_remove { self.asks.remove(&p); }
                }
                Side::Ask => {
                    let mut to_remove = Vec::new();
                    let mut iter_keys: Vec<u64> = self.bids.keys().cloned().collect();
                    iter_keys.sort_unstable_by(|a, b| b.cmp(a));
                    for bid_price in iter_keys {
                        if bid_price < price.0 || incoming.remaining.0 == 0 { break; }
                        if let Some(level) = self.bids.get_mut(&bid_price) {
                            while let Some(maker) = level.front().cloned() {
                                if incoming.remaining.0 == 0 { break; }
                                if prevent_self_trade && maker.owner == owner {
                                    return Err(error::Error::SelfTradePrevented);
                                }
                                let trade_qty = incoming.remaining.0.min(maker.remaining.0);
                                if trade_qty == 0 { break; }
                                
                                let total = trade_qty.saturating_mul(bid_price);
                                let maker_fee = total.saturating_mul(maker_fee_bps) / 10000;
                                let taker_fee = total.saturating_mul(taker_fee_bps) / 10000;
                                
                                incoming.remaining.0 -= trade_qty;
                                level.pop_front();
                                
                                let mut maker_updated = maker.clone();
                                maker_updated.remaining.0 -= trade_qty;
                                maker_updated.updated_at = now;
                                maker_updated.status = if maker_updated.remaining.0 == 0 {
                                    OrderStatus::Filled
                                } else {
                                    OrderStatus::PartiallyFilled
                                };
                                
                                if maker_updated.remaining.0 > 0 {
                                    level.push_front(maker_updated.clone());
                                }
                                self.order_index.insert(maker.id, maker_updated);
                                
                                // Track positions
                                *self.user_positions.entry(owner).or_insert(0) -= trade_qty as i64;
                                *self.user_positions.entry(maker.owner).or_insert(0) += trade_qty as i64;
                                
                                trades.push(Trade {
                                    taker_id: incoming.id,
                                    maker_id: maker.id,
                                    taker_owner: incoming.owner,
                                    maker_owner: maker.owner,
                                    taker_side: Side::Ask,
                                    price: Price(bid_price),
                                    quantity: Quantity(trade_qty),
                                    maker_fee,
                                    taker_fee,
                                    timestamp: now,
                                });
                            }
                            if level.is_empty() { to_remove.push(bid_price); }
                        }
                        if incoming.remaining.0 == 0 { break; }
                    }
                    for p in to_remove { self.bids.remove(&p); }
                }
            }
        }
        
        // Handle time-in-force rules
        match time_in_force {
            TimeInForce::FOK => {
                // Fill-or-kill: if not fully filled, cancel
                if incoming.remaining.0 > 0 {
                    incoming.status = OrderStatus::Rejected;
                    return Ok((id, vec![])); // No trades executed
                }
            }
            TimeInForce::IOC => {
                // Immediate-or-cancel: cancel any remaining
                if incoming.remaining.0 > 0 {
                    incoming.status = OrderStatus::Cancelled;
                    return Ok((id, trades));
                }
            }
            TimeInForce::GTC => {
                // Good-til-cancel: add remaining to book
                if incoming.remaining.0 > 0 {
                    incoming.status = if incoming.remaining.0 < original_qty {
                        OrderStatus::PartiallyFilled
                    } else {
                        OrderStatus::Open
                    };
                    incoming.updated_at = now;
                    
                    match side {
                        Side::Bid => {
                            self.bids.entry(price.0).or_default().push_back(incoming.clone());
                        }
                        Side::Ask => {
                            self.asks.entry(price.0).or_default().push_back(incoming.clone());
                        }
                    }
                    self.add_order_to_index(incoming);
                } else {
                    incoming.status = OrderStatus::Filled;
                }
            }
        }
        
        self.check_stop_orders();
        
        Ok((id, trades))
    }

    pub fn cancel(&mut self, id: OrderId) -> bool {
        // Check stop orders first
        if let Some(pos) = self.stop_orders.iter().position(|o| o.id == id) {
            self.stop_orders.remove(pos);
            self.remove_order_from_index(id);
            return true;
        }
        
        // Check bids
        for (_p, level) in self.bids.iter_mut() {
            if let Some(pos) = level.iter().position(|o| o.id == id) {
                level.remove(pos);
                self.remove_order_from_index(id);
                return true;
            }
        }
        
        // Check asks
        for (_p, level) in self.asks.iter_mut() {
            if let Some(pos) = level.iter().position(|o| o.id == id) {
                level.remove(pos);
                self.remove_order_from_index(id);
                return true;
            }
        }
        
        false
    }
    
    /// Place a stop-loss order (triggers market order when price reaches stop)
    pub fn place_stop_loss(&mut self, owner: OwnerId, side: Side, stop_price: Price, qty: Quantity) -> Result<OrderId> {
        if qty.0 > self.risk_limits.max_order_size {
            return Err(error::Error::OrderSizeTooLarge);
        }
        self.check_position_limit(owner, side, qty.0)?;
        
        let id = self.alloc_id();
        let now = timestamp_now();
        let order = Order {
            id,
            owner,
            side,
            order_type: OrderType::StopLoss,
            price: Price(0), // Market price when triggered
            quantity: qty,
            remaining: qty,
            time_in_force: TimeInForce::IOC,
            post_only: false,
            stop_price: Some(stop_price),
            status: OrderStatus::Open,
            created_at: now,
            updated_at: now,
        };
        
        self.stop_orders.push(order.clone());
        self.add_order_to_index(order);
        Ok(id)
    }
    
    /// Place a stop-limit order (triggers limit order when price reaches stop)
    pub fn place_stop_limit(&mut self, owner: OwnerId, side: Side, stop_price: Price, 
                            limit_price: Price, qty: Quantity) -> Result<OrderId> {
        if qty.0 > self.risk_limits.max_order_size {
            return Err(error::Error::OrderSizeTooLarge);
        }
        self.check_position_limit(owner, side, qty.0)?;
        
        let id = self.alloc_id();
        let now = timestamp_now();
        let order = Order {
            id,
            owner,
            side,
            order_type: OrderType::StopLimit,
            price: limit_price,
            quantity: qty,
            remaining: qty,
            time_in_force: TimeInForce::GTC,
            post_only: false,
            stop_price: Some(stop_price),
            status: OrderStatus::Open,
            created_at: now,
            updated_at: now,
        };
        
        self.stop_orders.push(order.clone());
        self.add_order_to_index(order);
        Ok(id)
    }
    
    /// Check and trigger stop orders based on current market price
    fn check_stop_orders(&mut self) {
        let last_price = self.get_last_trade_price();
        if last_price.is_none() {
            return;
        }
        let last = last_price.unwrap().0;
        
        let mut triggered = Vec::new();
        for (idx, order) in self.stop_orders.iter().enumerate() {
            if let Some(stop_price) = order.stop_price {
                let should_trigger = match order.side {
                    Side::Bid => last >= stop_price.0,  // Buy stop: trigger when price goes up
                    Side::Ask => last <= stop_price.0,  // Sell stop: trigger when price goes down
                };
                
                if should_trigger {
                    triggered.push((idx, order.clone()));
                }
            }
        }
        
        // Remove triggered orders (reverse order to maintain indices)
        for (idx, _) in triggered.iter().rev() {
            self.stop_orders.remove(*idx);
        }
        
        // Execute triggered orders
        for (_, order) in triggered {
            match order.order_type {
                OrderType::StopLoss => {
                    let _ = self.place_market(order.owner, order.side, order.quantity);
                }
                OrderType::StopLimit => {
                    let _ = self.place_limit(order.owner, order.side, order.price, 
                                            order.quantity, order.time_in_force, false);
                }
                _ => {}
            }
        }
    }
    
    fn get_last_trade_price(&self) -> Option<Price> {
        // Would typically get from trades list, for now use best bid/ask midpoint
        let bid = self.best_bid();
        let ask = self.best_ask();
        match (bid, ask) {
            (Some(b), Some(a)) => Some(Price((b.0 + a.0) / 2)),
            (Some(b), None) => Some(b),
            (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }
    
    /// Modify an existing order (price and/or quantity)
    pub fn modify_order(&mut self, id: OrderId, new_price: Option<Price>, new_qty: Option<Quantity>) -> Result<bool> {
        // For simplicity, we cancel and replace
        if let Some(order) = self.order_index.get(&id).cloned() {
            if !self.cancel(id) {
                return Ok(false);
            }
            
            let price = new_price.unwrap_or(order.price);
            let qty = new_qty.unwrap_or(order.quantity);
            
            if order.order_type == OrderType::Limit {
                let _ = self.place_limit(order.owner, order.side, price, qty, 
                                        order.time_in_force, order.post_only)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }
    
    /// Get all orders for a user
    pub fn get_user_orders(&self, owner: OwnerId) -> Vec<Order> {
        self.user_orders
            .get(&owner)
            .map(|order_ids| {
                order_ids.iter()
                    .filter_map(|id| self.order_index.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get user's current position
    pub fn get_user_position(&self, owner: OwnerId) -> i64 {
        self.user_positions.get(&owner).copied().unwrap_or(0)
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
        self.order_index.get(&id).cloned()
    }
    
    /// Get aggregated order book depth
    pub fn get_depth_aggregated(&self, price_step: u64, depth: usize) -> OrderBookSnapshot {
        let mut bid_levels: BTreeMap<u64, u64> = BTreeMap::new();
        let mut ask_levels: BTreeMap<u64, u64> = BTreeMap::new();
        
        // Aggregate bids
        for (price, level) in &self.bids {
            let bucket = (price / price_step) * price_step;
            let qty: u64 = level.iter().map(|o| o.remaining.0).sum();
            *bid_levels.entry(bucket).or_insert(0) += qty;
        }
        
        // Aggregate asks
        for (price, level) in &self.asks {
            let bucket = (price / price_step) * price_step;
            let qty: u64 = level.iter().map(|o| o.remaining.0).sum();
            *ask_levels.entry(bucket).or_insert(0) += qty;
        }
        
        let bids: Vec<(Price, u64)> = bid_levels.iter()
            .rev()
            .take(depth)
            .map(|(p, q)| (Price(*p), *q))
            .collect();
            
        let asks: Vec<(Price, u64)> = ask_levels.iter()
            .take(depth)
            .map(|(p, q)| (Price(*p), *q))
            .collect();
        
        OrderBookSnapshot { bids, asks }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookSnapshot {
    pub bids: Vec<(Price, u64)>,
    pub asks: Vec<(Price, u64)>,
}

/// Market analytics for tracking trade history and statistics
#[derive(Clone, Serialize, Deserialize)]
pub struct MarketAnalytics {
    trades: VecDeque<Trade>,
    candles_1m: VecDeque<Candle>,
    candles_5m: VecDeque<Candle>,
    candles_1h: VecDeque<Candle>,
    max_trades: usize,
    max_candles: usize,
}

impl Default for MarketAnalytics {
    fn default() -> Self {
        Self::new(10000, 1440) // ~10k trades, 24h of 1m candles
    }
}

impl MarketAnalytics {
    pub fn new(max_trades: usize, max_candles: usize) -> Self {
        Self {
            trades: VecDeque::with_capacity(max_trades),
            candles_1m: VecDeque::with_capacity(max_candles),
            candles_5m: VecDeque::with_capacity(max_candles / 5),
            candles_1h: VecDeque::with_capacity(max_candles / 60),
            max_trades,
            max_candles,
        }
    }
    
    pub fn add_trades(&mut self, new_trades: &[Trade]) {
        for trade in new_trades {
            self.trades.push_back(trade.clone());
            if self.trades.len() > self.max_trades {
                self.trades.pop_front();
            }
            self.update_candles(trade);
        }
    }
    
    fn update_candles(&mut self, trade: &Trade) {
        Self::update_candle_series(&mut self.candles_1m, trade, 60, self.max_candles);
        Self::update_candle_series(&mut self.candles_5m, trade, 300, self.max_candles);
        Self::update_candle_series(&mut self.candles_1h, trade, 3600, self.max_candles);
    }
    
    fn update_candle_series(candles: &mut VecDeque<Candle>, trade: &Trade, interval: u64, max_candles: usize) {
        let bucket = (trade.timestamp / interval) * interval;
        
        if let Some(last) = candles.back_mut() {
            if last.timestamp == bucket {
                // Update existing candle
                last.high = Price(last.high.0.max(trade.price.0));
                last.low = Price(last.low.0.min(trade.price.0));
                last.close = trade.price;
                last.volume += trade.quantity.0;
                last.num_trades += 1;
                return;
            }
        }
        
        // Create new candle
        let candle = Candle {
            timestamp: bucket,
            open: trade.price,
            high: trade.price,
            low: trade.price,
            close: trade.price,
            volume: trade.quantity.0,
            num_trades: 1,
        };
        
        candles.push_back(candle);
        if candles.len() > max_candles {
            candles.pop_front();
        }
    }
    
    pub fn get_candles(&self, interval: &str, limit: usize) -> Vec<Candle> {
        let candles = match interval {
            "1m" => &self.candles_1m,
            "5m" => &self.candles_5m,
            "1h" => &self.candles_1h,
            _ => &self.candles_1m,
        };
        
        candles.iter().rev().take(limit).cloned().collect()
    }
    
    pub fn get_recent_trades(&self, limit: usize) -> Vec<Trade> {
        self.trades.iter().rev().take(limit).cloned().collect()
    }
    
    pub fn get_24h_stats(&self) -> MarketStats {
        let now = timestamp_now();
        let day_ago = now.saturating_sub(86400);
        
        let trades_24h: Vec<&Trade> = self.trades.iter()
            .filter(|t| t.timestamp >= day_ago)
            .collect();
        
        if trades_24h.is_empty() {
            return MarketStats {
                last_price: None,
                price_change_24h: 0,
                high_24h: None,
                low_24h: None,
                volume_24h: 0,
                num_trades_24h: 0,
            };
        }
        
        let last_price = trades_24h.last().map(|t| t.price);
        let first_price = trades_24h.first().map(|t| t.price.0).unwrap_or(0);
        let price_change = last_price.map(|p| p.0 as i64 - first_price as i64).unwrap_or(0);
        
        let high = trades_24h.iter().map(|t| t.price.0).max().map(Price);
        let low = trades_24h.iter().map(|t| t.price.0).min().map(Price);
        let volume: u64 = trades_24h.iter().map(|t| t.quantity.0).sum();
        
        MarketStats {
            last_price,
            price_change_24h: price_change,
            high_24h: high,
            low_24h: low,
            volume_24h: volume,
            num_trades_24h: trades_24h.len() as u64,
        }
    }
}

pub trait OrderBookEngine: Send + Sync {
    fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity, 
                   time_in_force: TimeInForce, post_only: bool) -> Result<(OrderId, Vec<Trade>)>;
    fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)>;
    fn place_stop_loss(&self, owner: OwnerId, side: Side, stop_price: Price, qty: Quantity) -> Result<OrderId>;
    fn place_stop_limit(&self, owner: OwnerId, side: Side, stop_price: Price, 
                        limit_price: Price, qty: Quantity) -> Result<OrderId>;
    fn cancel(&self, id: OrderId) -> Result<bool>;
    fn modify_order(&self, id: OrderId, new_price: Option<Price>, new_qty: Option<Quantity>) -> Result<bool>;
    fn snapshot(&self, depth: usize) -> OrderBookSnapshot;
    fn get_depth_aggregated(&self, price_step: u64, depth: usize) -> OrderBookSnapshot;
    fn recent_trades(&self, limit: usize) -> Vec<Trade>;
    fn get_candles(&self, interval: &str, limit: usize) -> Vec<Candle>;
    fn get_24h_stats(&self) -> MarketStats;
    fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64);
    fn get_order(&self, id: OrderId) -> Option<Order>;
    fn get_user_orders(&self, owner: OwnerId) -> Vec<Order>;
    fn get_user_position(&self, owner: OwnerId) -> i64;
    fn as_any(&self) -> &dyn Any;
}

/// In-memory engine implementing OrderBookEngine
pub struct InMemoryEngine {
    book: Arc<RwLock<OrderBook>>,
    analytics: Arc<RwLock<MarketAnalytics>>,
}

impl InMemoryEngine {
    pub fn new() -> Self { 
        Self { 
            book: Arc::new(RwLock::new(OrderBook::new())), 
            analytics: Arc::new(RwLock::new(MarketAnalytics::default())),
        } 
    }
    
    pub fn with_config(fee_config: FeeConfig, risk_limits: RiskLimits) -> Self {
        Self {
            book: Arc::new(RwLock::new(OrderBook::with_config(fee_config, risk_limits))),
            analytics: Arc::new(RwLock::new(MarketAnalytics::default())),
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let book = self.book.read();
        let analytics = self.analytics.read();
        let snapshot = (&*book, &*analytics);
        let bytes = bincode::serialize(&snapshot).map_err(|e| anyhow!("serialize snapshot: {}", e))?;
        if let Some(dir) = path.parent() { fs::create_dir_all(dir).ok(); }
        fs::write(path, bytes).map_err(|e| anyhow!("persist orderbook: {}", e))?;
        Ok(())
    }

    pub fn load_from_path(&self, path: &Path) -> Result<()> {
        if !path.exists() { return Ok(()); }
        let bytes = fs::read(path).map_err(|e| anyhow!("load orderbook: {}", e))?;
        if let Ok((book_ser, analytics_ser)) = bincode::deserialize::<(OrderBook, MarketAnalytics)>(&bytes) {
            *self.book.write() = book_ser;
            *self.analytics.write() = analytics_ser;
        }
        Ok(())
    }
}

impl Default for InMemoryEngine {
    fn default() -> Self { Self::new() }
}

impl OrderBookEngine for InMemoryEngine {
    fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity, 
                   time_in_force: TimeInForce, post_only: bool) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_limit(owner, side, price, qty, time_in_force, post_only)?;
        if !trades.is_empty() {
            let mut analytics = self.analytics.write();
            analytics.add_trades(&trades);
        }
        Ok((id, trades))
    }
    
    fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_market(owner, side, qty)?;
        if !trades.is_empty() {
            let mut analytics = self.analytics.write();
            analytics.add_trades(&trades);
        }
        Ok((id, trades))
    }
    
    fn place_stop_loss(&self, owner: OwnerId, side: Side, stop_price: Price, qty: Quantity) -> Result<OrderId> {
        let mut book = self.book.write();
        book.place_stop_loss(owner, side, stop_price, qty)
    }
    
    fn place_stop_limit(&self, owner: OwnerId, side: Side, stop_price: Price, 
                        limit_price: Price, qty: Quantity) -> Result<OrderId> {
        let mut book = self.book.write();
        book.place_stop_limit(owner, side, stop_price, limit_price, qty)
    }
    
    fn cancel(&self, id: OrderId) -> Result<bool> {
        let mut book = self.book.write();
        Ok(book.cancel(id))
    }
    
    fn modify_order(&self, id: OrderId, new_price: Option<Price>, new_qty: Option<Quantity>) -> Result<bool> {
        let mut book = self.book.write();
        book.modify_order(id, new_price, new_qty)
    }
    
    fn snapshot(&self, depth: usize) -> OrderBookSnapshot {
        let book = self.book.read();
        book.snapshot(depth)
    }
    
    fn get_depth_aggregated(&self, price_step: u64, depth: usize) -> OrderBookSnapshot {
        let book = self.book.read();
        book.get_depth_aggregated(price_step, depth)
    }
    
    fn recent_trades(&self, limit: usize) -> Vec<Trade> {
        let analytics = self.analytics.read();
        analytics.get_recent_trades(limit)
    }
    
    fn get_candles(&self, interval: &str, limit: usize) -> Vec<Candle> {
        let analytics = self.analytics.read();
        analytics.get_candles(interval, limit)
    }
    
    fn get_24h_stats(&self) -> MarketStats {
        let analytics = self.analytics.read();
        analytics.get_24h_stats()
    }
    fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) {
        let book = self.book.read();
        let mut remaining = qty.0;
        let mut filled = 0u64;
        let mut cost = 0u64;
        match side {
            Side::Bid => {
                for (p, level) in book.bids.iter() {
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
    
    fn get_order(&self, id: OrderId) -> Option<Order> { 
        self.book.read().find_order(id) 
    }
    
    fn get_user_orders(&self, owner: OwnerId) -> Vec<Order> {
        self.book.read().get_user_orders(owner)
    }
    
    fn get_user_position(&self, owner: OwnerId) -> i64 {
        self.book.read().get_user_position(owner)
    }
    
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
        self.place_limit_advanced(owner, side, price, qty, TimeInForce::GTC, false)
    }
    
    pub fn place_limit_advanced(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity,
                                time_in_force: TimeInForce, post_only: bool) -> Result<(OrderId, Vec<Trade>)> {
        if price.0 == 0 { return Err(anyhow!("price must be > 0").into()); }
        if qty.0 == 0 { return Err(anyhow!("quantity must be > 0").into()); }
        let res = self.engine.place_limit(owner, side, price, qty, time_in_force, post_only);
        if res.is_ok() { self.try_save_snapshot(); }
        res
    }
    
    pub fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        if qty.0 == 0 { return Err(anyhow!("quantity must be > 0").into()); }
        let res = self.engine.place_market(owner, side, qty);
        if res.is_ok() { self.try_save_snapshot(); }
        res
    }
    
    pub fn place_stop_loss(&self, owner: OwnerId, side: Side, stop_price: Price, qty: Quantity) -> Result<OrderId> {
        if stop_price.0 == 0 { return Err(anyhow!("stop price must be > 0").into()); }
        if qty.0 == 0 { return Err(anyhow!("quantity must be > 0").into()); }
        let res = self.engine.place_stop_loss(owner, side, stop_price, qty);
        if res.is_ok() { self.try_save_snapshot(); }
        res
    }
    
    pub fn place_stop_limit(&self, owner: OwnerId, side: Side, stop_price: Price, 
                            limit_price: Price, qty: Quantity) -> Result<OrderId> {
        if stop_price.0 == 0 { return Err(anyhow!("stop price must be > 0").into()); }
        if limit_price.0 == 0 { return Err(anyhow!("limit price must be > 0").into()); }
        if qty.0 == 0 { return Err(anyhow!("quantity must be > 0").into()); }
        let res = self.engine.place_stop_limit(owner, side, stop_price, limit_price, qty);
        if res.is_ok() { self.try_save_snapshot(); }
        res
    }
    
    pub fn cancel(&self, id: OrderId) -> Result<bool> {
        if id.0 == 0 { return Err(anyhow!("invalid order id").into()); }
        let res = self.engine.cancel(id);
        if res.as_ref().unwrap_or(&false) == &true { self.try_save_snapshot(); }
        res
    }
    
    pub fn modify_order(&self, id: OrderId, new_price: Option<Price>, new_qty: Option<Quantity>) -> Result<bool> {
        if id.0 == 0 { return Err(anyhow!("invalid order id").into()); }
        let res = self.engine.modify_order(id, new_price, new_qty);
        if res.as_ref().unwrap_or(&false) == &true { self.try_save_snapshot(); }
        res
    }
    
    pub fn orderbook(&self, depth: usize) -> OrderBookSnapshot { 
        self.engine.snapshot(depth) 
    }
    
    pub fn orderbook_aggregated(&self, price_step: u64, depth: usize) -> OrderBookSnapshot {
        self.engine.get_depth_aggregated(price_step, depth)
    }
    
    pub fn recent_trades(&self, limit: usize) -> Vec<Trade> { 
        self.engine.recent_trades(limit) 
    }
    
    pub fn get_candles(&self, interval: &str, limit: usize) -> Vec<Candle> {
        self.engine.get_candles(interval, limit)
    }
    
    pub fn get_24h_stats(&self) -> MarketStats {
        self.engine.get_24h_stats()
    }
    
    pub fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) { 
        self.engine.estimate_market_cost(side, qty) 
    }
    
    pub fn get_order(&self, id: OrderId) -> Option<Order> { 
        self.engine.get_order(id) 
    }
    
    pub fn get_user_orders(&self, owner: OwnerId) -> Vec<Order> {
        self.engine.get_user_orders(owner)
    }
    
    pub fn get_user_position(&self, owner: OwnerId) -> i64 {
        self.engine.get_user_position(owner)
    }
}

impl Default for DexService {
    fn default() -> Self { Self::new() }
}

/// Sled-backed persistent engine implementing OrderBookEngine
pub struct SledEngine {
    db: sled::Db,
    book: Arc<RwLock<OrderBook>>,
    analytics: Arc<RwLock<MarketAnalytics>>,
}

const SLED_KEY_BOOK: &str = "book";
const SLED_KEY_ANALYTICS: &str = "analytics";

impl SledEngine {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() { let _ = fs::create_dir_all(dir); }
        let db = sled::open(path).map_err(|e| anyhow!("sled open: {}", e))?;
        let book = if let Ok(Some(val)) = db.get(SLED_KEY_BOOK) {
            bincode::deserialize::<OrderBook>(&val).unwrap_or_else(|_| OrderBook::new())
        } else { OrderBook::new() };
        let analytics = if let Ok(Some(val)) = db.get(SLED_KEY_ANALYTICS) {
            bincode::deserialize::<MarketAnalytics>(&val).unwrap_or_else(|_| MarketAnalytics::default())
        } else { MarketAnalytics::default() };
        Ok(Self {
            db,
            book: Arc::new(RwLock::new(book)),
            analytics: Arc::new(RwLock::new(analytics)),
        })
    }

    fn persist(&self) -> Result<()> {
        let book = self.book.read();
        let analytics = self.analytics.read();
        let book_bytes = bincode::serialize(&*book).map_err(|e| anyhow!("serialize book: {}", e))?;
        let analytics_bytes = bincode::serialize(&*analytics).map_err(|e| anyhow!("serialize analytics: {}", e))?;
        self.db.insert(SLED_KEY_BOOK, book_bytes).map_err(|e| anyhow!("sled put book: {}", e))?;
        self.db.insert(SLED_KEY_ANALYTICS, analytics_bytes).map_err(|e| anyhow!("sled put analytics: {}", e))?;
        self.db.flush().map_err(|e| anyhow!("sled flush: {}", e))?;
        Ok(())
    }
}

impl OrderBookEngine for SledEngine {
    fn place_limit(&self, owner: OwnerId, side: Side, price: Price, qty: Quantity,
                   time_in_force: TimeInForce, post_only: bool) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_limit(owner, side, price, qty, time_in_force, post_only)?;
        if !trades.is_empty() {
            let mut analytics = self.analytics.write();
            analytics.add_trades(&trades);
        }
        drop(book);
        self.persist()?;
        Ok((id, trades))
    }

    fn place_market(&self, owner: OwnerId, side: Side, qty: Quantity) -> Result<(OrderId, Vec<Trade>)> {
        let mut book = self.book.write();
        let (id, trades) = book.place_market(owner, side, qty)?;
        if !trades.is_empty() {
            let mut analytics = self.analytics.write();
            analytics.add_trades(&trades);
        }
        drop(book);
        self.persist()?;
        Ok((id, trades))
    }
    
    fn place_stop_loss(&self, owner: OwnerId, side: Side, stop_price: Price, qty: Quantity) -> Result<OrderId> {
        let mut book = self.book.write();
        let id = book.place_stop_loss(owner, side, stop_price, qty)?;
        drop(book);
        self.persist()?;
        Ok(id)
    }
    
    fn place_stop_limit(&self, owner: OwnerId, side: Side, stop_price: Price, 
                        limit_price: Price, qty: Quantity) -> Result<OrderId> {
        let mut book = self.book.write();
        let id = book.place_stop_limit(owner, side, stop_price, limit_price, qty)?;
        drop(book);
        self.persist()?;
        Ok(id)
    }

    fn cancel(&self, id: OrderId) -> Result<bool> {
        let mut book = self.book.write();
        let ok = book.cancel(id);
        drop(book);
        self.persist()?;
        Ok(ok)
    }
    
    fn modify_order(&self, id: OrderId, new_price: Option<Price>, new_qty: Option<Quantity>) -> Result<bool> {
        let mut book = self.book.write();
        let ok = book.modify_order(id, new_price, new_qty)?;
        drop(book);
        self.persist()?;
        Ok(ok)
    }

    fn snapshot(&self, depth: usize) -> OrderBookSnapshot { 
        self.book.read().snapshot(depth) 
    }
    
    fn get_depth_aggregated(&self, price_step: u64, depth: usize) -> OrderBookSnapshot {
        self.book.read().get_depth_aggregated(price_step, depth)
    }
    
    fn recent_trades(&self, limit: usize) -> Vec<Trade> {
        self.analytics.read().get_recent_trades(limit)
    }
    
    fn get_candles(&self, interval: &str, limit: usize) -> Vec<Candle> {
        self.analytics.read().get_candles(interval, limit)
    }
    
    fn get_24h_stats(&self) -> MarketStats {
        self.analytics.read().get_24h_stats()
    }
    fn estimate_market_cost(&self, side: Side, qty: Quantity) -> (u64, u64) {
        let book = self.book.read();
        let mut remaining = qty.0;
        let mut filled = 0u64;
        let mut cost = 0u64;
        match side {
            Side::Bid => {
                for (p, level) in book.bids.iter() {
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
    
    fn get_order(&self, id: OrderId) -> Option<Order> { 
        self.book.read().find_order(id) 
    }
    
    fn get_user_orders(&self, owner: OwnerId) -> Vec<Order> {
        self.book.read().get_user_orders(owner)
    }
    
    fn get_user_position(&self, owner: OwnerId) -> i64 {
        self.book.read().get_user_position(owner)
    }
    
    fn as_any(&self) -> &dyn Any { self }
}

/// Multi-market registry for managing multiple trading pairs
pub struct MarketRegistry {
    markets: Arc<RwLock<HashMap<MarketId, Market>>>,
    engines: Arc<RwLock<HashMap<MarketId, Arc<dyn OrderBookEngine>>>>,
    next_market_id: Arc<RwLock<u64>>,
}

impl Default for MarketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MarketRegistry {
    pub fn new() -> Self {
        Self {
            markets: Arc::new(RwLock::new(HashMap::new())),
            engines: Arc::new(RwLock::new(HashMap::new())),
            next_market_id: Arc::new(RwLock::new(1)),
        }
    }
    
    pub fn create_market(&self, base_asset: String, quote_asset: String, 
                        price_decimals: u8, quantity_decimals: u8, 
                        min_order_size: u64, fee_config: FeeConfig, 
                        risk_limits: RiskLimits) -> MarketId {
        let mut next_id = self.next_market_id.write();
        let id = MarketId(*next_id);
        *next_id += 1;
        drop(next_id);
        
        let market = Market {
            id,
            base_asset,
            quote_asset,
            price_decimals,
            quantity_decimals,
            min_order_size,
        };
        
        let engine = Arc::new(InMemoryEngine::with_config(fee_config, risk_limits));
        
        self.markets.write().insert(id, market);
        self.engines.write().insert(id, engine);
        
        id
    }
    
    pub fn get_market(&self, id: MarketId) -> Option<Market> {
        self.markets.read().get(&id).cloned()
    }
    
    pub fn get_engine(&self, id: MarketId) -> Option<Arc<dyn OrderBookEngine>> {
        self.engines.read().get(&id).cloned()
    }
    
    pub fn list_markets(&self) -> Vec<Market> {
        self.markets.read().values().cloned().collect()
    }
    
    pub fn get_market_by_symbol(&self, base: &str, quote: &str) -> Option<MarketId> {
        let markets = self.markets.read();
        markets.iter()
            .find(|(_, m)| m.base_asset == base && m.quote_asset == quote)
            .map(|(id, _)| *id)
    }
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



