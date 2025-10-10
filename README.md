Mini Tachyon
============

Rust workspace that prototypes a Tachyon-style shielded system: wallet with proof-carrying data (PCD), oblivious sync, pruning validator, and content-addressed networking.

Scope: experimental, credit to Sean Bowe & Zcash team


What this is
------------
- **Wallet**: keeps encrypted notes, witnesses, and a PCD state. Syncs via OSS using blobs; builds spends
- **OSS (Oblivious Sync Service)**: publishes deltas and transition blobs so wallets can advance state without revealing secrets.
- **Node extension**: validates PCD proofs and enforces a sliding nullifier window; prunes old state.
- **Accumulators**: MMR for commitments, sparse set for nullifiers; support batched deltas and witness updates.
- **Header sync**: simplified bootstrap/checkpoint flow.
- **Networking**: `iroh` + `iroh-blobs` for transport and content addressing.


Workspace layout
----------------
`crates/`:
- `net_iroh`: network layer over iroh/iroh-blobs. Control messages, blob publish/fetch, tickets.
- `accum_mmr`: append-only Merkle Mountain Range, deltas, witness maintenance.
- `accum_set`: sparse set accumulator for nullifiers, batched deltas.
- `pcd_core`: PCD state, transitions, verification glue. Hash-bound mock proofs right now.
- `circuits`: halo2 wiring for transition/aggregation (mock prover today).
- `wallet`: high-level wallet API: DB, sync loop, OOB payments, tx build skeleton.
- `oss_service`: delta/transition publishing loop, access tokens, rate limits.
- `node_ext`: validator shim: verify PCD, enforce nullifier window, prune.
- `header_sync`: simple checkpoint/header bootstrap.
- `pq_crypto`: Kyber KEM + AES-GCM for OOB; simple VRF-ish nullifier blinding; signing helpers.
- `storage`: encrypted wallet DB: notes, PCD checkpoints, witnesses, OOB keys.
- `cli`: `tachyon` command; wallet and network subcommands.
- `bench`: async harness to exercise MMR, PCD, network, crypto, storage.


Data model
----------
- `PcdState { anchor_height, state_commitment, mmr_root, nullifier_root, block_hash, proof, ... }`
- `PcdTransition { prev_state_commitment, new_state_commitment, mmr_delta, nullifier_delta, block_height_range, transition_proof }`
- Deltas are bincode’d batches from `accum_mmr::MmrDelta` and `accum_set::SetDelta`.
- Proofs are mock (hash-bound) until circuits are fully wired.


Flows
-----
- **Sync**: wallet subscribes → fetches blobs via tickets → applies deltas via `pcd_core` → updates `PcdState` → persists.
- **Spend (skeleton)**: wallet selects notes → builds spend bundle → attaches `PcdState` proof at anchor.
- **Validation**: node verifies PCD, checks nullifiers against a recent window, prunes historical state.
- **OOB payment**: Kyber encapsulation → AEAD encrypt note meta → recipient decapsulates → wallet ingests note.

Crypto:
Searching the codebase for signature schemes and crypto libraries.


[3 tools called]

Checking `crates/pq_crypto/src/lib.rs` for signature schemes.


[2 tools called]

Checking for other signature schemes in networking and dependencies.


[2 tools called]

Checking Cargo.lock for signature-related dependencies.


[1 tool called]

## Signature Schemes Used in Tachyon Mini

### 1. **Dilithium3 (Post-Quantum Digital Signatures)**
- **Library**: `pqcrypto-dilithium = "0.5"`
- **Location**: `crates/pq_crypto/src/lib.rs`
- **Usage**: Suite B signing API for checkpoint verification
- **Features**:
  - Dilithium3 key generation (`SuiteB::generate_keypair()`)
  - Prehashed signing with BLAKE3 (`SuiteB::sign_prehash()`)
  - Signature verification (`SuiteB::verify_prehash()`)
  - Domain-separated hashing for checkpoint signing

### 2. **Ed25519 (via ed25519-dalek)**
- **Library**: `ed25519-dalek` (transitive dependency)
- **Usage**: Networking layer (likely via iroh/libp2p)
- **Features**: Ed25519 signatures for peer identity and authentication

### 3. **Ring-based Cryptography**
- **Library**: `ring = "0.17.14"` (transitive dependency)
- **Usage**: TLS/SSL via rustls
- **Features**: ECDSA signatures for TLS certificates

### 4. **Pairing-based Cryptography**
- **Library**: `pairing = "0.23.0"` (transitive dependency)
- **Usage**: Zero-knowledge proofs (halo2)
- **Features**: BLS signatures and pairing operations

## Additional Cryptographic Components

### **Kyber768 (Post-Quantum KEM)**
- **Library**: `pqcrypto-kyber = "0.8"`
- **Usage**: Key encapsulation for out-of-band payments
- **Features**: Kyber768 key generation, encapsulation, and decapsulation

### **AES-256-GCM**
- **Library**: `aes-gcm = "0.10"`
- **Usage**: Symmetric encryption for out-of-band payments
- **Features**: Authenticated encryption with associated data

### **BLAKE3**
- **Library**: `blake3 = "1.5"`
- **Usage**: Hashing, nullifier derivation, and signature prehashing
- **Features**: Fast cryptographic hashing

## Summary

The project uses:
1. **Primary signature scheme**: Dilithium3 (post-quantum)
2. **Networking signatures**: Ed25519 (via iroh/libp2p)
3. **TLS signatures**: ECDSA (via rustls/ring)
4. **ZK proof signatures**: BLS/pairing-based (via halo2)


CLI
---
Install toolchain: rustup stable. Build from workspace root.

- Wallet
  - Create: `cargo run -p cli -- wallet create --name test --password pass`
  - Info: `cargo run -p cli -- wallet info --db-path ./tachyon_data/wallets/test --password pass`
  - Notes: `cargo run -p cli -- wallet list-notes --db-path ... --password ... [--unspent-only]`
  - OOB URI: `cargo run -p cli -- wallet oob-uri --db-path ... --password ...`
  - Create OOB payment: `cargo run -p cli -- wallet create-payment --recipient-pk 0x.. --value 123 --db-path ... --password ...`
  - Receive OOB payment: `cargo run -p cli -- wallet receive-payment --payment-data '<json>' --db-path ... --password ...`
  - Sync: `cargo run -p cli -- wallet sync --db-path ... --password ...`

- Network
  - Start node: `cargo run -p cli -- network node --data-dir ./tachyon_data --listen-addr 0.0.0.0:8080 [--bootstrap-nodes a,b]`
  - Publish blob: `cargo run -p cli -- network publish --file ./blob.bin --kind pcd_transition --height 42`


Assumptions & non-goals
-----------------------
- Fixed demo keys, localhost relay, permissive defaults; safe for local dev only.
- Proofs are mock; performance numbers are aspirational.
- OSS auth/rate limit is minimal.
- API surfaces may change.


Build & run
-----------
- Build: `cargo build` (or `--release`)
- Bench: `cargo run -p bench --release`


Credits
-------
Idea inspired by Tachyon and Sean Bowe’s writing.


