# Mini Tachyon

This repository is a Rust workspace that tries recreate the Tachyon-style shielded payment flow so I can check whether the moving pieces actually fit. It focuses on oblivious wallet synchronization, proof-carrying data (PCD), and validator pruning. Production hardening is out of scope. Credit:  Sean Bowe - https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/

Status: experiment

## What it currently does
- keeps wallet state as a PCD object so validators can stay minimal
- generates and consumes accumulator deltas for commitments and nullifiers
- moves out-of-band (OOB) payments with a post-quantum KEM + AEAD wrapper
- sketches an Oblivious Sync Service (OSS) that hands wallets the blobs they need
- exposes a CLI (`tachyon`) for the usual wallet lifecycle tasks

## Workspace layout
- `crates/wallet` – wallet state, sync client, OOB helpers
- `crates/pcd_core` – PCD state machine, transitions, verifier glue
- `crates/circuits` – Halo2 demo circuits and folding scaffold
- `crates/accum_mmr` – Merkle Mountain Range accumulator for commitments
- `crates/accum_set` – sparse accumulator for nullifiers and membership proofs
- `crates/pq_crypto` – Kyber-style KEM placeholders, blinded nullifier derivation, OOB payloads
- `crates/node_ext` – validator-side helpers for PCD + pruning
- `crates/header_sync` – NiPoPoW-style header bootstrap sketch
- `crates/storage` – encrypted storage facade
- `crates/oss_service` – OSS prototype
- `crates/cli` – binary called `tachyon`
- `crates/bench` – quick microbench harnesses

## Build and test
```bash
cargo build
```
```bash
cargo test
```
```bash
cargo run -p bench -- quick
```

## CLI quick look
Most commands want a wallet database path and password. Defaults are for demos only. You can opt into insecure shortcuts with `TACHYON_ALLOW_INSECURE=1` when you understand the trade-offs.

```bash
tachyon wallet create --name demo --password test --db-path ./demo_wallet
```
```bash
tachyon wallet oob-uri --db-path ./demo_wallet --password test
```
```bash
# recipient_pk is the hex string from the recipient URI
tachyon wallet create-payment \
  --recipient-pk 0x<recipient_kyber_pk_hex> \
  --value 12345 \
  --db-path ./sender_wallet \
  --password test
# emits a JSON blob you pass along some other channel
```
```bash
# payment_json is the blob from the sender
tachyon wallet oob-parse \
  --payment-json '...json...' \
  --db-path ./demo_wallet \
  --password test
```
```bash
tachyon wallet info --db-path ./demo_wallet --password test
```
```bash
tachyon wallet list-notes --db-path ./demo_wallet --password test
```
```bash
tachyon wallet sync --db-path ./demo_wallet --password test
```

## Concept map
- PCD: `pcd_core::PcdState` captures anchor height, commitment root, nullifier root, and proof bytes. `PcdTransition` ties prior and new state values while circuits in `crates/circuits` prove consistency. `PcdSyncManager` batches transitions so wallets avoid full replay.
- Accumulators: commitments go through `accum_mmr::MmrAccumulator`; nullifiers live in `accum_set::SetAccumulator`. Deltas apply in `pcd_core` before proof updates.
- OOB payments: `pq_crypto::OutOfBandPayment` rides on a Kyber-like KEM plus AES-GCM to encrypt note metadata. Wallet helpers form and parse these payloads.
- Nullifiers: `pq_crypto::derive_nullifier(commitment, rseed, mode)` defaults to the blinded mode to leak less to the OSS.

## Environment knobs
Wallet config looks at:
- `TACHYON_DB_PATH`
- `TACHYON_MASTER_PASSWORD`
- `TACHYON_IROH_DATA_DIR`
- `TACHYON_BOOTSTRAP_NODES`
- `TACHYON_OSS_ENDPOINTS`
- `TACHYON_SYNC_INTERVAL_SECS`
- `TACHYON_MAX_SYNC_BATCH_SIZE`
- `TACHYON_ALLOW_INSECURE`

## Security notes
- Cryptography in `pq_crypto` and the Halo2 circuits are prototype-grade. Do not point real value at this.
- Validator, OSS, and aggregation paths are deliberately simplified for iteration speed.
- Assume missing controls for DoS, replay handling, and side-channel resistance.

If you are here, you probably want to read the code, not this file. I agree.
