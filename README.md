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
- `pcd_core`: PCD state, transitions, verification glue. Uses Halo2 proofs for transitions.
- `circuits`: Halo2 transition circuit with Poseidon binding; real prover/verifier.
- `wallet`: high-level wallet API: DB, sync loop, OOB payments, tx build skeleton.
- `oss_service`: delta/transition publishing loop, access tokens, rate limits.
- `node_ext`: validator shim: verify PCD, enforce nullifier window, prune.
- `header_sync`: simple checkpoint/header bootstrap.
- `pq_crypto`: Kyber KEM + AES-GCM for OOB; simple VRF-ish nullifier blinding; signing helpers.
- `storage`: encrypted wallet DB: notes, PCD checkpoints, witnesses, OOB keys.
- `cli`: `tachyon` command; wallet and network subcommands.
- `bench`: async harness to exercise MMR, PCD, network, crypto, storage.
- `qerkle`: dynamic-hash Merkle tree (BLAKE3 + Poseidon) with Kyber-encrypted metadata and inclusion proofs.


Data model
----------
- `PcdState { anchor_height, state_commitment, mmr_root, nullifier_root, block_hash, proof, ... }`
- `PcdTransition { prev_state_commitment, new_state_commitment, mmr_delta, nullifier_delta, block_height_range, transition_proof }`
- Deltas are bincode’d batches from `accum_mmr::MmrDelta` and `accum_set::SetDelta`.
- Proofs are Halo2-based for state transitions (no mocks/stubs).


Flows
-----
- **Sync**: wallet subscribes → fetches blobs via tickets → applies deltas via `pcd_core` → updates `PcdState` → persists.
- **Spend (skeleton)**: wallet selects notes → builds spend bundle → attaches `PcdState` proof at anchor.
- **Validation**: node verifies PCD, checks nullifiers against a recent window, prunes historical state.
- **OOB payment**: Kyber encapsulation → AEAD encrypt note meta → recipient decapsulates → wallet ingests note.
- **Qerkle (experimental)**: build dynamic-hash Merkle roots using per-level hash choices; produce inclusion proofs that carry sibling path and hash-choice bits; optionally encrypt root+seed metadata with Kyber for distribution.


Adopt Out-of-Band Payments (no protocol changes)
------------------------------------------------
Enable immediate usability wins for shielded wallets by exchanging notes off-chain. This requires no changes to the Zcash protocol or consensus.

- URI format (shareable recipient handle):
  - `tachyon:oobpay?pk=0x<kyber-pk-hex>&scheme=kyber768`

CLI quickstart
--------------
1) Receiver: get an OOB recipient URI and share it via any channel
   - `cargo run -p cli -- wallet oob-uri --db-path ./tachyon_data/wallets/alice --password pass`

2) Sender: create an OOB payment JSON for that recipient
   - `cargo run -p cli -- wallet create-payment --recipient-pk 0x<pk-hex> --value 123 --db-path ./tachyon_data/wallets/bob --password pass`
   - Output is a small JSON blob. Send it to the recipient out-of-band (QR, link, messenger, email).

3) Receiver: ingest the OOB payment JSON; the note is decrypted and saved immediately
   - `cargo run -p cli -- wallet receive-payment --payment-data '<json>' --db-path ./tachyon_data/wallets/alice --password pass`
   - Verify: `cargo run -p cli -- wallet list-notes --db-path ./tachyon_data/wallets/alice --password pass`

API integration (Rust)
----------------------
Minimal steps wallets need to add to support OOB send/receive:

```rust
// 1) Receiver publishes a shareable OOB URI (contains Kyber public key)
let pk = wallet.get_oob_public_key().await; // serialize as 0x<hex>

// 2) Sender creates an OOB payment JSON
// Note metadata layout:
// [commitment(32) | value(8) | recipient(32) | rseed(32) | memo_len(2) | memo(..)]
let payment = wallet_sender
    .create_oob_payment(pk, note_metadata_bytes, b"app_context".to_vec())
    .await?;
let json = serde_json::to_string(&payment)?; // share via any channel

// 3) Receiver ingests and persists the payment
let hash = wallet_receiver.receive_oob_payment(payment).await?;
let _note = wallet_receiver.process_oob_payment(&hash).await?; // persisted automatically
```

Notes
-----
- Works entirely out-of-band; no changes to Zcash consensus or transaction formats.
- Uses Kyber768 KEM + AES-GCM. `associated_data` can bind app/channel context.
- Keys are stored per-wallet; URIs can be rotated without on-chain impact.
- Payments are normal spendable notes once ingested; they’ll appear in `list-notes`.

Qerkle usage (dev)
------------------
- Build a root from 32-byte leaves with deterministic choice seed:
  - Rust API: see `qerkle::QerkleBuilder::build_root` and `create_proof`.
- Verify inclusion:
  - `InclusionProof::verify(leaf, &root, index)` returns true on success.
- Encrypt metadata (root + seed) for a recipient:
  - `EncryptedMetadata::encrypt(&KyberPublicKey, root, seed)` / `decrypt(&KyberSecretKey)`.

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

- Wallet (simplified one-liners)
  - Create: `cargo run -p cli -- wallet create --name alice --password pass`
  - Share URI: `cargo run -p cli -- wallet share --name alice --password pass`
  - Send OOB: `cargo run -p cli -- wallet send-oob --from bob --password pass --to "tachyon:oobpay?pk=0x.." --value 123 [--memo "hi"]`
  - Claim OOB: `cargo run -p cli -- wallet claim-oob --name alice --password pass --json '<payment-json>'`
  - Info: `cargo run -p cli -- wallet info --db-path ./tachyon_data/wallets/alice --password pass`
  - Notes: `cargo run -p cli -- wallet list-notes --db-path ./tachyon_data/wallets/alice --password pass [--unspent-only]`
  - Sync: `cargo run -p cli -- wallet sync --db-path ./tachyon_data/wallets/alice --password pass`

- Network
  - Start node: `cargo run -p cli -- network node --data-dir ./tachyon_data --listen-addr 0.0.0.0:8080 [--bootstrap-nodes a,b]`
  - Publish blob: `cargo run -p cli -- network publish --file ./blob.bin --kind pcd_transition --height 42`


Assumptions & non-goals
-----------------------
- Fixed demo keys, localhost relay, permissive defaults; safe for local dev only.
- Transition proofs are real Halo2; performance numbers are still aspirational.
- OSS auth/rate limit is minimal.
- API surfaces may change.


Build & run
-----------
- Build: `cargo build` (or `--release`)
- Bench: `cargo run -p bench --release`


Credits
-------
Idea inspired by Tachyon and Sean Bowe’s writing.


