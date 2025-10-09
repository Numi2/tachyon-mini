# Mini Tachyon

This repository is a Rust workspace that tries recreate the Tachyon-style shielded payment flow so I can check whether the moving pieces actually fit. It focuses on oblivious wallet synchronization, proof-carrying data (PCD), and validator pruning. Production hardening is out of scope. Credit:  Sean Bowe - https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/

Status: experiment

keeps wallet state as a PCD object so validators can stay minimal
generates and consumes accumulator deltas for commitments and nullifiers
moves out-of-band (OOB) payments with a post-quantum KEM + AEAD wrapper
sketches an Oblivious Sync Service (OSS) that hands wallets the blobs they need
exposes a CLI (tachyon) for the usual wallet lifecycle tasks
---

# Mini Tachyon Architecture Guide

This document walks through each crate in the repository, explains the role it plays in the Tachyon prototype, and highlights the main interactions between crates. The goal is to give new contributors a fast on-ramp to the system’s moving parts.

## High-Level Picture

At its core, Mini Tachyon is a proof-carrying-data (PCD) wallet prototype that tracks commitments in a Merkle Mountain Range (MMR), manages a nullifier accumulator, and synchronizes via an “oblivious sync service” over an iroh-based gossip network.

```
wallet ─┬─ storage (encrypted DB)
        ├─ pcd_core (state machine & transitions)
        ├─ pq_crypto (OOB payments & primitives)
        ├─ accum_mmr / accum_set (commitments + nullifiers)
        └─ net_iroh (blob transport & control plane)
             ├─ header_sync     (chain bootstrap)
             └─ oss_service     (delta + state publisher)
node_ext ── validates blocks via pcd_core + accumulators
bench    ── exercises the stack end-to-end
cli      ── front-end for wallet + network ops
```

## Crate Reference

### `accum_mmr`
- Implements a Merkle Mountain Range tailored for 32-byte “tachygram” leaves, including proof generation (`MmrProof`), membership proofs (`TachygramMembershipProof`), delta batching (`MmrDelta`), and persistence hooks (`MmrStorage`).
- Exposes an `MmrAccumulator` used by both the wallet’s `pcd_core` state machine and the `oss_service` when constructing commitment updates.

### `accum_set`
- Provides a sparse set accumulator backed by `BTreeSet<[u8; 32]>` with batchable deltas (`SetDelta`) and placeholder membership witnesses.
- Used anywhere nullifier membership/non-membership needs to be tracked; `pcd_core` consumes deltas during state transitions, and `oss_service` produces blinded nullifier batches.

### `bench`
- An async benchmark harness (`TachyonBenchmark`) orchestrating multiple subsystems: MMR operations, PCD state/transition proof flows, network blob upload/download, crypto primitives, and storage access.
- Valuable both as a regression detector and as sample code demonstrating crate integration.

### `circuits`
- Halo2-based circuit for PCD transitions and recursion (`PcdTransitionCircuit`, `PcdRecursionCircuit`), plus helper logic for deterministic mixing/hash simulation.
- `PcdCore` (in `pcd_core`) leans on this crate to produce mock proofs and to verify placeholder proofs in tests and during transitions.

### `cli`
- User-facing command-line front end wrapping wallet actions (`tachyon wallet …`) and network node tasks (`tachyon network …`).
- Calls into the `wallet` crate for database-backed operations, uses `net_iroh` to publish blobs, and configures `node_ext` when running a node.
- Demonstrates end-to-end flows: creating wallets, generating OOB payments, syncing state, or launching a local network node.

### `header_sync`
- Simplified NiPoPoW-inspired header chain manager (`HeaderSyncManager`) that can bootstrap from checkpoints, maintain a map of block headers, and periodically sync via the network.
- Uses `net_iroh::TachyonNetwork` to talk to peers, `pq_crypto::SuiteB` for checkpoint signatures, and persists headers to disk.

### `net_iroh`
- Thin wrapper over `iroh` + `iroh-blobs` providing:
  - `TachyonNetwork`: sets up an endpoint, manages control-plane channels (`ControlMessage`), publishes blobs with tickets, and broadcasts announcements.
  - `TachyonBlobStore`: local blob persistence/cache.
- Other crates (wallet, OSS, header sync, benchmarks) rely on this layer for data movement.

### `node_ext`
- “Validator” shim for pulling data off the network, verifying PCD proofs (`SimplePcdVerifier`), enforcing nullifier windows, aggregating proofs, and pruning state.
- Consumes `accum_mmr`, `accum_set`, `pcd_core`, `net_iroh`, and `pq_crypto`.
- Offers hooks a production node would need: block validation (`validate_block`), transaction verification, background pruning, and state tracking.

### `oss_service`
- Oblivious Sync Service publishing batched deltas and transition proofs on an interval.
- Generates `PcdDeltaBundle`s via `accum_mmr`/`accum_set`, produces `PcdTransition`s using `pcd_core`, and pushes blobs to the network through `net_iroh`.
- Tracks wallet subscriptions, rate-limits clients, and keeps an in-memory record of published tickets for consumption by wallets.

### `pcd_core`
- Heart of the proof-carrying-data model:
  - `PcdState`, `PcdTransition`, and `PcdDeltaBundle` types.
  - `PcdStateMachine` applies deltas to accumulators (`accum_mmr`, `accum_set`), rebinds commitments, and uses `circuits::PcdCore` to produce/verify mock proofs.
  - `PcdStateManager` adds verification/persistence hooks, while `PcdSyncManager` orchestrates incremental or bundled synchronization via a `PcdSyncClient`.
- Shared by wallet, node extension, OSS service, and benchmarks.

### `pq_crypto`
- Collection of crypto utilities:
  - Kyber KEM/AES-GCM for out-of-band payments (`OutOfBandPayment`).
  - Nullifier blinding via epoch-based VRF (`BlindedNullifier`, `derive_nullifier`).
  - Suite-B (Dilithium3 + BLAKE3) signing for checkpoints.
  - Rate-limiting tokens and padding helpers for privacy-preserving requests.
- Consumed by wallet, OSS, header sync, storage, and node extension.

### `storage`
- Encrypted on-disk store for wallet state (`WalletDatabase`), notes (`EncryptedNote`), PCD checkpoints (`PcdStateRecord`), witnesses (`WitnessRecord`), and OOB key material.
- Provides atomic persistence, in-memory caches, and helpers for deriving encryption keys from the master password.
- Used exclusively by the `wallet` crate.

### `wallet`
- High-level wallet API:
  - Handles configuration, initial PCD state bootstrap, background sync task, and network integration.
  - Wraps the encrypted database, PCD state manager, sync manager, OOB payment handler, and transaction builder.
  - Interfaces with `net_iroh` (blob announcements), `pcd_core` (state updates), `pq_crypto` (OOB payments, nullifiers), and `storage` (durable state).

## Data & Control Flows

1. **State Evolution**  
   - The wallet maintains a `PcdState` via `pcd_core::PcdStateManager`.  
   - The OSS service periodically publishes `MmrDelta`, `SetDelta`, and `PcdTransition` blobs with tickets through `net_iroh`.  
   - Wallets (via `WalletSyncClient`) listen for `BlobKind::PcdTransition`, fetch tickets, and apply transitions using `PcdStateManager`, persisting to `storage`.

2. **Commitment & Nullifier Management**  
   - `accum_mmr::MmrAccumulator` tracks note commitments; `accum_set::SetAccumulator` tracks nullifiers.
   - Deltas originate in the OSS, are applied in the wallet/node via `pcd_core`, and validated in `node_ext`.

3. **Network Layer**  
   - `net_iroh::TachyonNetwork` handles all blob distribution: wallet sync data, OSS outputs, benchmarks, and header sync.
   - Control messages allow announcing new blobs and subscribing to specific `BlobKind`s.

4. **Wallet Operations**  
   - `storage::WalletDatabase` encrypts/decrypts notes and states under a master key derived from the user password.
   - OOB payments use Kyber KEM/AES through `pq_crypto`; the CLI provides helpers (`wallet create`, `wallet receive-payment`, etc.).

5. **Validation & Monitoring**  
   - `node_ext` monitors the network, aggregates proofs, and maintains a sliding window of nullifiers to prevent double spends.
   - `bench` crate offers performance visibility across MMR, PCD, network, crypto, and storage paths.

## Getting Started Tips

- For CLI-driven testing, run `cargo run -p cli -- wallet create …` to set up a wallet, then explore sync or OOB flows.
- The benchmark suite (`cargo run -p bench --release`) exercises multiple crates concurrently—useful when changing core primitives.
- If you are modifying circuit logic, touch `circuits` first, then adjust `pcd_core::PcdStateMachine` to match any new constraints.
- Networking or blob distribution tweaks belong in `net_iroh`; both OSS and wallet sync clients consume its APIs.

## Where to Go Next

- **Storage or wallet features:** focus on `storage`, `wallet`, and their interaction with `pcd_core`.
- **Networking or sync logic:** look at `net_iroh`, `oss_service`, and `header_sync`.
- **Cryptography experiments:** start in `pq_crypto`, then wire the results through wallet/node flows.
- **Validation path:** explore `node_ext` alongside `pcd_core` to understand how proofs and nullifiers are enforced.

---
