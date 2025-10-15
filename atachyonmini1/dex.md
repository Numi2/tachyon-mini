## DEX architecture, implementation details, and roadmap

This document explains the in-memory DEX engine, storage ledger design, wallet integration, CLI UX, and a concise roadmap for next iterations.

### What we built
- A DEX module embedded under `wallet::dex` with a pluggable matching engine interface (`OrderBookEngine`) and an `InMemoryEngine` implementation.
- A `DexService` facade wrapping an engine, exposing simple APIs: limit/market order placement, cancel, orderbook snapshot, recent trades, and market-cost estimation.
- `storage` generalized balances using a token ledger (`TokenLedger`) and added atomic settlement helpers. Legacy balances migrate to `balances_v2.bin` automatically on first load.
- `wallet` integrated `DexService`, added deposit/get-balance calls, and uses atomic settlement during order fills.
- CLI improvements: default `~/.tachyon`, password prompt support, `--format {table,json}`, new DEX commands (including market orders and watch).

## Components

### wallet::dex module
- `OrderBookEngine` trait (pluggable engine boundary):
  - place_limit(owner, side, price, qty) -> (order_id, trades)
  - place_market(owner, side, qty) -> (order_id, trades)
  - cancel(order_id) -> bool
  - snapshot(depth) -> bids/asks levels
  - recent_trades(limit) -> trades
  - estimate_market_cost(side, qty) -> (filled_qty, quote_cost)
  - get_order(order_id) -> Option<Order>

- `InMemoryEngine`:
  - Price-time priority using two maps of price levels (bids/asks), FIFO per level.
  - Simple trade log (ring buffer semantics via capped VecDeque).
  - Persistence helpers: `save_to_path(path)`, `load_from_path(path)` to serialize `(OrderBook, VecDeque<Trade>)` via bincode. Wiring is optional (see Roadmap).

- `DexService` (facade):
  - Default constructed with `InMemoryEngine`.
  - `with_engine(...)` allows swapping to an external engine later.

### storage crate
- Replaced fixed fields with a generalized token ledger (`TokenLedger`) that stores `HashMap<Token, BalanceRecord { available, locked }>` plus token metadata (e.g., decimals).
- Migration: If `balances_v2.bin` is absent but legacy `balances.bin` exists, legacy balances are migrated to v2 and persisted.
- Atomic settlement helpers:
  - `settle_bid_fill(base_qty, quote_cost)` atomically spends locked USDC and credits base.
  - `settle_ask_fill(base_qty, quote_gain)` atomically spends locked base and credits USDC.
- Generic helpers for credit/debit/lock/unlock/spend_locked for any token; convenience wrappers remain for USDC/BASE.

### wallet crate
- Holds a `DexService` instance and wires methods:
  - Get balances (available and locked).
  - Deposit USDC/base (for demo/testing) using ledger helpers.
  - Place limit orders: lock funds up-front, call engine, settle fills atomically per trade.
  - Place market orders: estimate quote spend (bids) or lock base (asks), execute market, settle fills, then refund unused locks.
  - Cancel orders: unlock remaining locked funds for that order.

### CLI
- Global polish:
  - `--format {table,json}` (default table) for machine-readable output.
  - Default data dir `~/.tachyon` with tilde expansion.
  - Password prompts for DEX commands when `--password` omitted; `--non-interactive` forbids prompts.

- DEX commands (examples):
```bash
# Show balances
tachyon --format table dex balance --db-path ~/.tachyon/wallets/alice

# Deposits (demo/testing funds)
tachyon dex deposit-usdc --db-path ~/.tachyon/wallets/alice --amount 1000000
tachyon dex deposit-base --db-path ~/.tachyon/wallets/alice --amount 25

# Place orders
tachyon dex place-limit --db-path ~/.tachyon/wallets/alice --side bid --price 100 --qty 10
tachyon dex place-market --db-path ~/.tachyon/wallets/alice --side ask --qty 5

# Inspect orderbook/trades
tachyon dex orderbook --db-path ~/.tachyon/wallets/alice --depth 10 --format json
tachyon dex trades --db-path ~/.tachyon/wallets/alice --limit 20

# Watch (polling)
tachyon dex watch --db-path ~/.tachyon/wallets/alice --depth 10 --interval-ms 1000
```

## Data model and invariants
- Quantities and prices use `u64` (integers). USDC decimal handling is via metadata; for MVP we treat values as integer minor units.
- Ledger updates for fills are atomic within a single write-lock on the ledger, preventing interleaving inconsistencies.
- Locks:
  - Bids lock quote (USDC), asks lock base. Fills decrement locked, credits the opposing asset.
  - Market bids lock estimated cost; refunds unlock after execution.

## Persistence
- `InMemoryEngine` provides `save_to_path` and `load_from_path` helpers for serializing `(OrderBook, Trades)` to a file.
- Currently not auto-wired; see Roadmap for automatic integration with wallet lifecycle.

## Testing guidance
- Unit tests: engine matching paths, ledger migration and atomic updates.
- E2E CLI tests (temp dirs): create wallet → deposit → limit bid + matching ask → verify balances, orderbook, trades.
- Add property-based tests for aggregate invariants: sums preserved, no negative balances, no overspends from available vs locked.

## Known limitations
- Single-market (`BASE/USDC`) only; no symbol registry.
- `u64` price/qty; no overflow guards beyond saturating additions; consider checked math for prod.
- No fee model; ownership model is simplified (`OwnerId(1)` in wallet), not multi-tenant safe.
- Persistence helpers are opt-in and not yet integrated with startup/shutdown.

## Roadmap

### P0 (short-term)
- Wire engine persistence automatically
  - Tech: use `bincode` snapshots in `<wallet_db>/dex/orderbook.bin` plus `orderbook.bin.tmp` atomic renames.
  - Choice: simple file snapshotting is sufficient for single-process in-memory engine; easy to reason about and test.
  - Implementation:
    - Load: wallet `new()` calls `InMemoryEngine::load_from_path(<db>/dex/orderbook.bin)` (ignore if missing).
    - Save: after limit/market/cancel, schedule a debounced write (e.g., 100–250 ms) to avoid excessive I/O; save on `shutdown()` too.

- Multi-market scaffolding
  - Tech: add `MarketId` (string or u128), `MarketConfig { base: TokenId, quote: TokenId, tick_size: u64, min_qty: u64, lot_size: u64, decimals }`.
  - Choice: keep markets in-memory as `HashMap<MarketId, InMemoryEngine>`; scales fine for small N and simplifies isolation.
  - Implementation: extend `DexService` with `get_market()` and pass-through APIs taking `MarketId`.

- Token registry
  - Tech: `storage::TokenLedger` gains registry methods `set_meta/get_meta`; CLI pretty-prints with decimals and symbol.
  - Choice: colocate metadata with ledger for now; later, external registry can be added.

- Fees (maker/taker)
  - Tech: configure per-market `FeeSchedule { maker_bps, taker_bps, fee_token }` and apply during settlement.
  - Choice: take fees in quote by default for `BASE/USDC`; record fee sink account (internal owner) in ledger.

### P1 (medium-term)
- External engine adapter (feature: `external_orderbook`)
  - Tech: feature-gated adapter module implementing `OrderBookEngine` to bridge to an external crate.
  - Choice: evaluate a lock-free engine (e.g., crossbeam/dashmap-based core akin to OrderBook-rs) for hotspot scaling.
  - Config: env or config file to select engine at runtime; keep CLI unchanged.

- Order lifecycle & ownership
  - Tech: persist owner-id to order-id map; expose `cancel(owner, id)`.
  - Add TIF: `enum TimeInForce { Gtc, Ioc, Fok }` and `post_only: bool` on order params.
  - Choice: validations in engine; settlement remains in wallet/storage.

- Observability
  - Tech: `tracing` spans for place/match/cancel; metrics via `metrics` + `metrics-exporter-prometheus`.
  - Choice: minimal overhead; Prometheus scraping works locally and in CI.

- Performance
  - Tech: `criterion` benches for synthetic mixes; profile with `pprof-rs`.
  - Choice: target reducing allocations in hot loops and minimizing copies per match.

### P2 (long-term)
- Persistence durability & recovery
  - Tech: append-only journal (`orderbook.journal`) with periodic `orderbook.bin` snapshots; recover by replay-then-snapshot.
  - Choice: avoids data loss between writes; simple, no external DB required. Consider SQLite if multi-process becomes a need.

- Risk controls
  - Tech: rule engine configured per-market: max notional per order, price bands (±X% from mid), per-owner position limits.
  - Choice: enforce pre-trade in engine; maintain owner exposures in memory with periodic persistence.

- Networking
  - Tech: add optional gRPC/tonic service for programmatic access; WebSocket (tokio-tungstenite) for streaming book/trades.
  - Choice: gRPC for typed APIs and client stubs; WS for UI dashboards.

- Integration (onramp/offramp)
  - Tech: finalize `onramp-stripe` flow to auto-credit USDC on verified webhook events; write to `TokenLedger` via atomic credit.
  - Choice: keep onramp isolated; DEX only depends on ledger credit events, not on Stripe-specific logic.

## Operational notes
- Dev profile allows insecure defaults; production should enforce:
  - Secure password sourcing (no plaintext flags), non-local endpoints, and guarded persistence paths.
  - Input validations on CLI (bounds, required fields).

## Upgrade/migration
- On first run post-upgrade, if only `balances.bin` exists, it is migrated to `balances_v2.bin` transparently.
- Future migrations should add a versioned ledger header to support rolling upgrades.

## Quick reference
- Engine swap: use `DexService::with_engine(Arc<dyn OrderBookEngine>)` to supply an alternative implementation.
- Atomic settlement helpers in `storage`:
  - `settle_bid_fill(base_qty, quote_cost)`
  - `settle_ask_fill(base_qty, quote_gain)`
- CLI JSON formatting for automation: add `--format json`.


