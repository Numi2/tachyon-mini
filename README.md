# Mini Tachyon

A research/prototype implementation of the Tachyon model for scalable, private shielded payments inspired by Sean Bowe's vision. This repository explores oblivious wallet synchronization, validator state pruning, and proof-carrying data (PCD) with simple, test-friendly components.

Status: experimental, not production-ready. 

## Highlights (aligned with Tachyon vision)
- Oblivious synchronization with PCD-backed wallet state in `pcd_core`
- Out-of-band (OOB) payments with KEM+AEAD envelopes in `pq_crypto` and wallet helpers
- Aggregated validator view: Merkle Mountain Range (MMR) for note commitments (`accum_mmr`) and a sparse accumulator for nullifiers (`accum_set`)
- Blinded nullifier derivation to reduce information leakage (`pq_crypto::derive_nullifier` with `Blinded` mode)
- CLI workflows for wallet operations and OOB payment URIs

## Repository structure
- `crates/wallet`: Wallet services: PCD state sync, note handling, OOB payment send/receive
- `crates/pcd_core`: PCD state, transitions, bundling, and verifier interface
- `crates/circuits`: Halo2-based circuits (demo-level constraints) and aggregation scaffolding
- `crates/accum_mmr`: MMR accumulator for note commitments
- `crates/accum_set`: Sparse set accumulator for nullifiers and (non-)membership deltas
- `crates/pq_crypto`: PQ-friendly KEM/AEAD placeholders, blinded nullifier derivation, OOB payments
- `crates/node_ext`: Validator/node extension: lightweight validation flow and block-level proof aggregation helper
- `crates/header_sync`: NiPoPoW-style header sync scaffold for fast bootstrapping
- `crates/storage`: Encrypted note/state storage interfaces
- `crates/oss_service`: Oblivious Sync Service (sketch)
- `crates/cli`: End-user command line interface
- `crates/bench`: Micro/quick benchmarks

## Build
```bash
cargo build
```
Run tests:
```bash
cargo test
```
(Optional) Run quick benchmarks:
```bash
cargo run -p bench -- quick
```

## CLI quickstart
The CLI binary is `tachyon` (see `crates/cli`). Many commands accept a wallet db path and password; defaults are convenient for local dev only. For demos, you can allow insecure defaults via an env var where noted in the code.

- Create a wallet directory:
```bash
tachyon wallet create --name demo --password test --db-path ./demo_wallet
```

- Show your OOB recipient URI (to share with a sender out-of-band):
```bash
tachyon wallet oob-uri --db-path ./demo_wallet --password test
```

- Create an OOB payment (on sender side):
```bash
# recipient_pk is hex from the recipient's URI
tachyon wallet create-payment \
  --recipient-pk 0x<recipient_kyber_pk_hex> \
  --value 12345 \
  --db-path ./sender_wallet \
  --password test
# Prints a JSON blob to share out-of-band (QR/URI/etc.)
```

- Receive/process an OOB payment (on recipient side):
```bash
# payment_json is the JSON blob produced by create-payment
tachyon wallet oob-parse \
  --payment-json '...json from sender...' \
  --db-path ./demo_wallet \
  --password test
```

- View wallet info and notes:
```bash
tachyon wallet info --db-path ./demo_wallet --password test
tachyon wallet list-notes --db-path ./demo_wallet --password test
```

- Sync (PCD state background sync is scaffolded; this triggers a manual sync):
```bash
tachyon wallet sync --db-path ./demo_wallet --password test
```

## Key concepts
- Proof-Carrying Data (PCD):
  - `pcd_core::PcdState` encapsulates the wallet anchor height, MMR root, nullifier root, and a proof.
  - `PcdTransition` binds prev/new state commitments and deltas; circuits live in `crates/circuits`.
  - `PcdSyncManager` sketches incremental/bundled sync.

- Accumulators:
  - Commitments: `accum_mmr::MmrAccumulator` supports append and delta application.
  - Nullifiers: `accum_set::SetAccumulator` supports batch insert/remove with a compact root commitment.
  - `pcd_core` applies deltas to both to update state roots.

- Out-of-band payments:
  - `pq_crypto::OutOfBandPayment` uses placeholder Kyber KEM + AES-GCM for encrypted note metadata.
  - Wallet exposes helpers to create/receive/process OOB payments.

- Nullifier derivation:
  - `pq_crypto::derive_nullifier(commitment, rseed, mode)` with `NullifierDerivationMode::{Legacy, Blinded}`.
  - Wallet defaults to `Blinded` for better privacy in oblivious sync.

## Environment configuration
Wallet honors a few env vars (see `WalletConfig::from_env()`):
- `TACHYON_DB_PATH`, `TACHYON_MASTER_PASSWORD`
- `TACHYON_IROH_DATA_DIR`, `TACHYON_BOOTSTRAP_NODES`
- `TACHYON_OSS_ENDPOINTS`, `TACHYON_SYNC_INTERVAL_SECS`, `TACHYON_MAX_SYNC_BATCH_SIZE`
- For local/dev demos that use default values, you may set `TACHYON_ALLOW_INSECURE=1`.

## Security and limitations
- Cryptography in `pq_crypto` and circuits in `crates/circuits` are demo-grade. Do not use for real funds.
- Many flows (aggregation, verification, OSS) are intentionally simplified for clarity and iteration speed.
