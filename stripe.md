Stripe Onramp + DEX Integration for Tachyon Wallet
==================================================

## Vision

Enable Tachyon wallet users to seamlessly acquire USDC via Stripe’s fiat-to-crypto onramp and immediately participate in decentralized trading of USDC vs base assets using the in-wallet DEX engine. Users get a clean, compliant entry point to crypto with Stripe handling KYC/AML and payments, while Tachyon focuses on private wallet operations and non-custodial trading mechanics.

## Goals

- Provide a production-grade onramp flow with Stripe, including webhook verification and reliable crediting of USDC to the wallet.
- Generalize the wallet token ledger to support USDC and base assets with locking and atomic settlement for DEX fills.
- Offer a minimal, pluggable DEX engine with order matching and settlement integrated into the wallet.
- Ship clear CLI ergonomics and docs to test and operate the end-to-end flow.

## Non-Goals

- Custodial key management or hosting Stripe UI ourselves. We leverage Stripe-hosted flows for PCI compliance and KYC/AML.
- Maintaining a centralized orderbook service in production; the provided engine is in-memory with an adapter surface for future persistence or external engines.

## Architecture Overview

- Wallet (`crates/wallet`): encrypted DB, PCD sync, token ledger (generalized), DEX interactions.
- Storage (`crates/storage`): encrypted storage and a generalized token ledger with available/locked balances for arbitrary tokens.
- DEX (`crates/dex`): `OrderBookEngine` trait with:
  - In-memory engine (default)
  - Sled-backed persistent engine (enabled by default under `<wallet_db>/dex_sled`)
- Onramp (`crates/onramp_stripe`): Stripe integration providing:
  - Create onramp session with destination address, network, and token.
  - Webhook server with signature verification and timestamp tolerance.
  - Persistent pending topups store (`FilePendingStore`) and claim flow to credit USDC to the wallet.
- CLI (`crates/cli`): adds `onramp` command group and expands `dex` commands.

### Flow: Buy USDC → Trade in DEX

1. User requests an onramp session (CLI creates session via Stripe API with destination address/network/currency).
2. User completes purchase on Stripe’s hosted flow.
3. Stripe sends `onramp.session.succeeded` (or similar) to our webhook.
4. Webhook verifies signature, then confirms the session via Stripe API (authoritative amount/currency/network).
5. A pending topup is persisted to disk.
6. User claims the pending topup into a chosen wallet; USDC is credited into the wallet’s token ledger.
7. User participates in the DEX using USDC (bids) or base asset (asks) with atomic settlement and refunds for residual locks.

## Stripe Integration Details

References: See Stripe Onramp docs at [docs.stripe.com/crypto/onramp](https://docs.stripe.com/crypto/onramp).

### API Calls

- Create session:
  - POST `https://api.stripe.com/v1/crypto/onramp/sessions`
  - Auth: Bearer `STRIPE_SECRET_KEY`
  - Params (form-encoded):
    - `destination_currency` (e.g., `usdc`)
    - `destination_network` (e.g., `ethereum`, `solana`, `polygon`, `avalanche`, `base`, `stellar`)
    - `destination_address` (user’s crypto address / wallet destination string)
    - `suggested_destination_amount` (minor units)
  - Response includes `id` and either `redirect_url` or `client_secret` to complete the flow.

- Fetch session details:
  - GET `https://api.stripe.com/v1/crypto/onramp/sessions/{id}`
  - Used to confirm status `succeeded`, and obtain authoritative `destination.amount`, `destination.currency`, `destination.network` (fallback to `amount_total`/`currency`).

### Webhook

- Endpoint: `/webhook/stripe` served by `onramp_stripe` via `axum`.
- Signature verification:
  - Validate `Stripe-Signature` header (HMAC-SHA256 over `timestamp.payload`) with `STRIPE_WEBHOOK_SECRET`.
  - Enforce a 5-minute timestamp tolerance window to prevent replay.
- Event handling:
  - On `onramp.session.succeeded` (or `checkout.session.completed` as a fallback), fetch full session details from Stripe using `STRIPE_SECRET_KEY`.
  - If currency is `usdc` and amount > 0, persist a pending topup `{session_id, usdc_amount}` in `FilePendingStore`.

### Persistence & Idempotency

- `FilePendingStore` maintains a JSON file of pending topups; directory is created if missing.
- Webhook enqueues idempotently by keying on `session_id`.
- `claim` removes the pending record and credits USDC; a second claim will fail with `not found`.

### Configuration

- Environment variables:
  - `STRIPE_SECRET_KEY`: API key (required for session creation and session lookups).
  - `STRIPE_WEBHOOK_SECRET`: webhook signing secret (recommended for production).

- Onramp runtime config (`OnrampConfig`):
  - `stripe_secret_key: String`
  - `webhook_secret: Option<String>`
  - `destination_address: String`
  - `destination_network: String` (default in CLI: `ethereum`)
  - `destination_currency: String` (default in CLI: `usdc`)

- Amounts are provided in minor units. For USDC with 6 decimals, `1 USDC = 1_000_000`.

## CLI Usage

### Create an onramp session

```bash
cargo run -p cli -- onramp create-session \
  --destination <wallet-address> \
  --network ethereum \
  --currency usdc \
  --amount 1000000
```

Outputs JSON with `{ id, url }`. Direct the user to `url` to complete purchase.

### Run the webhook server (development)

```bash
export STRIPE_SECRET_KEY=sk_test_xxx
export STRIPE_WEBHOOK_SECRET=whsec_xxx
cargo run -p cli -- onramp webhook \
  --listen 0.0.0.0:8787 \
  --pending-file ./onramp/pending.json
```

Configure Stripe to send webhooks to `http://<host>:8787/webhook/stripe` (or use `stripe listen` for tunneling in dev).

### List pending topups

```bash
cargo run -p cli -- onramp pending --pending-file ./onramp/pending.json
```

### Claim a topup into a wallet

```bash
cargo run -p cli -- onramp claim \
  --session-id <session-id> \
  --db-path <wallet_db_path> \
  --password <wallet_password> \
  --pending-file ./onramp/pending.json
```

Credits USDC into the wallet’s token ledger and removes the pending entry.

## Wallet + DEX Integration

- Generalized token ledger in `storage` supports arbitrary token symbols and separate `available` vs `locked` balances.
- DEX limit/market orders lock the appropriate balances:
  - Bids lock quote (USDC), Asks lock base.
  - On fills, atomic settlement moves from locked to counter-asset available (e.g., spend locked USDC → credit base).
  - On cancel or partial fill, residual locks are unlocked.
- The engine is pluggable via `OrderBookEngine`:
  - Default: persistent sled engine stored under `<wallet_db>/dex_sled`; survives restarts automatically.

### DEX Persistence Quickstart

```bash
cargo run -p cli -- dex place-limit --db-path <wallet> --password <pw> --side bid --price 100 --qty 5
# restart CLI/process and verify orders persist
cargo run -p cli -- dex order-book --db-path <wallet> --password <pw> --depth 10
```

## Security Considerations

- Webhook signature verification with timestamp tolerance.
- No logging of secrets; pass Stripe secrets via env/secure config.
- Consider IP allowlisting, TLS termination, and rate-limiting in production deployment.
- Persisted pending file only stores minimal data (session id, amount); avoid storing PII.

## Compliance & Geography

- Stripe is merchant of record; KYC/AML handled by Stripe. We do not collect or store KYC data.
- Respect Stripe-supported token/network availability by region (e.g., EU/US differences). Enforce via UI/CLI defaults or server policy.

## Observability & Reliability

- Webhook handler logs errors but remains idempotent; missed events can be replayed by Stripe or reconciled by session lookup cron.
- Consider adding a background reconciler to query recent sessions for the last N hours and backfill pending topups.
- Add basic metrics (events received, verified, enqueued, claimed) and alerts.

## Testing

- Use Stripe test mode API keys and `stripe listen` for local webhook forwarding.
- End-to-end:
  - Start webhook
  - Create session
  - Complete purchase in test mode
  - Verify pending JSON updated
  - Claim into a test wallet and verify `dex balance` shows credited USDC

## Roadmap

### Part 2: Atomic Settlement and Token Generalization

- Expand token metadata registry (decimals, symbols, networks) and enforce via ledger operations.
- Add journaled atomic updates for settlement to guard against process crashes (write-ahead log or transactional store).
- Support multi-token pairs and multi-market DEX (e.g., USDC/ZEC, USDC/BASE) with quote/base abstractions.
- Add precise decimal handling (e.g., `rust_decimal`) where required by UI, keeping the ledger in integer minor units.

### Part 3: Engine Trait + Adapter + Optional Persistence

- Solidify `OrderBookEngine` trait and provide adapters for:
  - In-memory engine (current)
  - Local persistent engine (e.g., RocksDB/sled)
  - Remote matching engine over gRPC/HTTP
- Add snapshot/restore for orderbook state and durable trade logs (append-only journal + checkpoints).
- Crash consistency: atomic multi-key updates (journaled writes) for place/cancel/fill sequences.
- Idempotent reapplication of journal on startup; periodic compaction into checkpoints.
- Introduce maker/taker fees (configurable) and fee accounting in ledger.
- Add concurrency controls (per-market locks) and deterministic matching policy (price-time priority, partial fills, cancels).

### Stripe Onramp Enhancements

- Add Embedded Onramp (web/app) once stable, and mobile SDK hooks when available.
- Add off-ramp exploration using Stripe Payouts where supported.
- Region-aware UI: dynamically filter networks/tokens by user locale.
- Operational tooling for rotating webhook secrets and API keys with zero-downtime.

## Operational Runbook (Prod)

- Secrets: inject `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` via secure secret store.
- Deploy webhook behind HTTPS with WAF/rate-limit; health checks and logging.
- Monitor webhook error rates and pending queue growth; alert on anomalies.
- Backup `pending.json` and rotate to a DB table if needed (idempotent upserts by `session_id`).
- If DEX persistence is enabled, back up `TACHYON_DEX_PERSIST_PATH` directory; consider snapshot + journal rotation schedule.
- Periodically reconcile by scanning recent sessions via Stripe API for missed events.

## Open Questions

- Destination address format standardization (per network) and validation in CLI.
- Multiple networks for USDC per region (Solana/Polygon/Base/Stellar) and routing logic.
- Handling of onramp refunds/chargebacks and reversing credited balances (requires negative adjustments and audit trail).


