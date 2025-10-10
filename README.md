Mini Tachyon
============

Rust workspace that prototypes a Tachyon-style shielded system: wallet with proof-carrying data (PCD), oblivious sync, pruning validator, and content-addressed networking.

Scope: experimental, credit to Sean Bowe & Zcash team


What this is
------------
- **Wallet**: keeps encrypted notes, witnesses, and a PCD state; derives FVKey-independent nullifiers (NF2) from a spend-secret; syncs via height-keyed Manifests; builds spends.
- **OSS (Oblivious Sync Service)**: publishes per-height Manifests that reference commitment MMR deltas, nullifier deltas, and PCD transition blobs. Peers see only content hashes/sizes.
- **Node extension**: maintains canonical commitment MMR and nullifier SetAccumulator; verifies PCD; enforces nullifier uniqueness across full history; prunes old state.
- **Accumulators**: MMR for commitments, sparse set for nullifiers; support batched deltas and witness updates.
- **Header sync**: simplified bootstrap/checkpoint flow.
- **Networking**: `iroh` + `iroh-blobs` for transport and content addressing; includes `BlobKind::Manifest` and a `SyncManifest` index by height.
- **Chain nullifier client (optional)**: wallet can query a Zebra HTTP endpoint for observed nullifiers using TLS (`reqwest` + `rustls`).
- **Witness maintenance**: after adopting a new PCD state, the wallet recomputes and persists MMR witnesses for all unspent notes.


Workspace layout
----------------
`crates/`:
- `net_iroh`: network layer over iroh/iroh-blobs. Control messages, blob publish/fetch, tickets, and per-height `SyncManifest` with `BlobKind::Manifest`.
- `accum_mmr`: append-only Merkle Mountain Range, deltas, witness maintenance.
- `accum_set`: sparse set accumulator for nullifiers, batched deltas.
- `pcd_core`: PCD state, transitions, verification glue. Uses Halo2 proofs for transitions.
- `circuits`: Halo2 transition circuit with Poseidon binding; real prover/verifier.
- `wallet`: high-level wallet API: DB, sync loop consuming Manifests, OOB payments, NF2 nullifiers, optional Zebra integration.
- `oss_service`: publishes per-height Manifests, commitment/nullifier deltas, and PCD transitions; access tokens & rate limits.
- `node_ext`: validator shim: verify PCD, enforce canonical nullifier uniqueness, match anchor roots, prune.
- `header_sync`: simple checkpoint/header bootstrap.
- `pq_crypto`: Kyber KEM + AES-GCM for OOB; NF2 PRFs (`derive_spend_nullifier_key`, `derive_nf2`); signing helpers.
- `storage`: encrypted wallet DB: notes, PCD checkpoints, witnesses, OOB keys, and an encrypted spend secret.
- `cli`: `tachyon` command; wallet and network subcommands.
- `bench`: async harness to exercise MMR, PCD, network, crypto, storage.
- `qerkle`: dynamic-hash Merkle tree (BLAKE3 + Poseidon) with Kyber-encrypted metadata and inclusion proofs.


Data model
----------
- `PcdState { anchor_height, state_commitment, mmr_root, nullifier_root, block_hash, proof, ... }`
- `PcdTransition { prev_state_commitment, new_state_commitment, mmr_delta, nullifier_delta, block_height_range, transition_proof }`
- Deltas are bincode’d batches from `accum_mmr::MmrDelta` and `accum_set::SetDelta`.
- Proofs are Halo2-based for state transitions (no mocks/stubs).
- `SyncManifest { height, items: Vec<ManifestItem{ kind, cid, size, ticket, height }] }` published per height; contains only public metadata.


Flows
-----
- **Sync**: wallet subscribes to Manifests → fetches per-height deltas/proofs via tickets → applies via `pcd_core` → updates `PcdState` → persists; OSS learns only CIDs/sizes.
- **Chain nullifier observation (optional)**: if `TACHYON_ZEBRA_NULLIFIER_URL` is set, the wallet fetches recent nullifiers, derives NF2 per unspent note, and flags locally-spent notes.
- **Spend (skeleton)**: wallet selects notes → derives NF2 using a spend secret (not from FVKey) → builds spend bundle → attaches `PcdState` proof at anchor.
- **Validation**: node verifies PCD, enforces nullifier uniqueness against the canonical set, and requires `anchor_height`, `mmr_root`, and `nullifier_root` to match the node’s canonical state; old state can be pruned.
- **OOB payment**: Kyber encapsulation → AEAD encrypt note meta → recipient decapsulates → wallet ingests note.
- **Qerkle (experimental)**: build dynamic-hash Merkle roots using per-level hash choices; produce inclusion proofs that carry sibling path and hash-choice bits; optionally encrypt root+seed metadata with Kyber for distribution.

Nullifiers (NF2)
----------------
- Goal: nullifiers must be uncomputable from any viewing key (FVKey) and only computable by the spend authority, while remaining publicly unique.
- Derivation implemented in `pq_crypto`:
  - `snk = PRF_snk(sk, "snk")`
  - `t = PRF_t(snk, ρ)`
  - `NF2 = H("orchard2.nf" || cm || ρ || t)`
- Wallet computes NF2 only when spending using a locally encrypted spend secret; OSS learns no spend hints.
- Node maintains one global nullifier set keyed by the revealed bytes; enforces uniqueness without extra secrets.

Configuration
-------------
Environment variables supported by the wallet (see `WalletConfig::from_env()`):

- `TACHYON_DB_PATH`: wallet database directory (default `./wallet_db`).
- `TACHYON_MASTER_PASSWORD`: password used to derive the DB master key.
- `TACHYON_IROH_DATA_DIR`: network data directory (default `./wallet_data`).
- `TACHYON_BOOTSTRAP_NODES`: comma-separated bootstrap peers.
- `TACHYON_OSS_ENDPOINTS`: comma-separated OSS endpoints (default `localhost:8080`).
- `TACHYON_SYNC_INTERVAL_SECS`: background sync period (default `30`).
- `TACHYON_MAX_SYNC_BATCH_SIZE`: max blocks per sync batch (default `10`).
- `TACHYON_ZEBRA_NULLIFIER_URL`: optional Zebra base URL (enables chain nullifier observation).
- `TACHYON_ALLOW_INSECURE=1`: allow localhost endpoints and default password for dev.

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

Cryptography (overview)
-----------------------
- Kyber768 (pq KEM) + AES-256-GCM for OOB note encryption.
- BLAKE3 for hashing and NF2 PRFs; Poseidon inside circuits.
- Halo2 for PCD transition proofs; Dilithium3 (Suite B) for checkpoint signing.


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

## Onramp (Stripe) Integration

The CLI includes an `onramp` command group that integrates Stripe's fiat-to-crypto onramp so users can buy USDC directly into their wallet, then trade via the DEX.

Prereqs:
- Set `STRIPE_SECRET_KEY` with your Stripe API key.
- Optionally set `STRIPE_WEBHOOK_SECRET` for webhook signature verification.

Commands:
- Create a session:
  `cargo run -p cli -- onramp create-session --destination <wallet-address> --amount 1000000`
- Start webhook server (dev):
  `cargo run -p cli -- onramp webhook --listen 0.0.0.0:8787 --pending-file ./onramp/pending.json`
- List pending topups:
  `cargo run -p cli -- onramp pending --pending-file ./onramp/pending.json`
- Claim a topup into a wallet:
  `cargo run -p cli -- onramp claim --session-id <id> --db-path <path> --password <pw> --pending-file ./onramp/pending.json`

Notes:
- Webhook endpoint is `/webhook/stripe`. Configure this URL in your Stripe dashboard or via `stripe listen` tunnel in development.
- Claimed USDC is credited to the wallet's generalized token ledger and is usable with the DEX commands.


