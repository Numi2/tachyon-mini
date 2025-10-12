Mini Tachyon
============

Rust workspace that prototypes a Tachyon-style shielded system: wallet with proof-carrying data (PCD), oblivious sync, pruning validator, and content-addressed networking.

Scope: experimental, credit to Sean Bowe & Zcash team


idea
------------------
- Two trees:
  - Tree 1: all coin commitments ever created (append-only).
  - Tree 2: all nullifiers of spent coins (insert-only; no deletes).

- at spend:
  1. Prove the coin is in the coin tree.
  2. Prove the spend nullifier is not in the nullifier tree.
  3. Insert the nullifier into the nullifier tree.

- Blocks:
  - One block-wide proof (Halo2 + Poseidon2) checks all spends, inserts, and new coins at once.
  - Validators verify only this succinct proof and update the two accumulators.

- resultat:
  - No deletions → simpler, faster accumulators and witness updates.
  - Wallets apply small per-block deltas.
  - Verifiers avoid replaying transactions; they check one succinct proof.


What this is
------------
- **Wallet**: keeps encrypted notes, witnesses, and a PCD state; derives FVKey-independent nullifiers (NF2) from a spend-secret; syncs via height-keyed Manifests; builds spends.
- **OSS (Oblivious Sync Service)**: publishes per-height Manifests that reference commitment MMR deltas, nullifier deltas, and PCD transition blobs. Peers see only content hashes/sizes.
- **Node extension**: maintains canonical commitment MMR and nullifier SetAccumulator; verifies PCD; enforces nullifier uniqueness across full history; prunes old state.
- **Accumulators**: MMR for commitments, sparse set for nullifiers; support batched deltas and witness updates.
- **Header sync**: simplified bootstrap/checkpoint flow, pooled HTTP client for Zebra headers.
- **Networking**: `iroh` + `iroh-blobs` for transport and content addressing; includes `BlobKind::Manifest` and a `SyncManifest` index by height.
- **Chain nullifier client )**: wallet can query a Zebra HTTP endpoint for observed nullifiers using TLS (`reqwest` + `rustls`).
- **Witness maintenance**: after adopting a new PCD state, the wallet recomputes and persists MMR witnesses for all unspent notes.
 - **Halo2 transition proofs )**: transitions are proven/verified with Halo2; legacy hash/mocks removed.
 - **Manifests from block data**: OSS consumes node-published deltas and publishes per-height manifests and PCD transitions only.
 - **Pruning journals**: node writes per-block journals and prunes beyond a retention window.


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


Tachygrams and Tachystamps (Prototype)
--------------------------------------
Tachyon-style shielded flows collapse commitments and nullifiers into indistinguishable 32-byte blobs called tachygrams and produce a single aggregated proof per transaction or block, called a tachystamp.

- Tachygram: `pcd_core::tachyon::Tachygram([u8; 32])`
  - Represents either a note commitment or a nullifier; indistinguishable to third parties.
- Anchor: `pcd_core::tachyon::TachyAnchor { height, mmr_root, nullifier_root }`
  - Binds proofs to the current chain accumulator roots and a recent height.
- Tachyaction: pair of tachygrams plus an authorization binding/signature.
  - Replaces Orchard actions in this prototype; signatures are stubs.
- Tachystamp: aggregated recursion proof over one-or-more action proofs.
  - Built via `pcd_core::tachyon::Tachystamp::new(anchor, grams, actions, proofs)` using Halo2 recursion.
  - Node verifies the aggregated proof and that anchor roots/height match the canonical state.

What’s new (ease-of-use)
------------------------
- `TachystampBuilder` (ergonomic API): construct stamps from simple hex strings without touching low-level types.
  - `TachystampBuilder::new(height, mmr_hex, nulls_hex)` → `.add_gram_hex(..)` / `.add_grams_csv(..)` → `.add_action_pair_hex(left_hex, right_hex, [sig_hex])` → `.build()`.
- Two new CLI helpers for fast experiments, no wallet required:
  - `tachyon tachy-build-stamp` – build a stamp from hex inputs and print JSON.
  - `tachyon tachy-verify-stamp` – verify a previously produced stamp JSON.
- Circuit glue for tachyactions lives in `circuits/src/tachy.rs`:
  - Computes a Poseidon digest for an action and binds it to a leaf update.
  - Includes a minimal authorizing-signature relation (toy), plus a sparse-Merkle path walk.
  - `RecursionCore` aggregates digests/proofs into a single 32-byte commitment.

Wallet
- Provides `wallet::TachyonWallet::build_tachystamp(...)` to package outputs/nullifiers into tachygrams, attach optional tachyactions, and aggregate provided proofs into a tachystamp bound to the current anchor.

Node
- Builds a block-level tachystamp by aggregating all tx proofs and collecting per-tx tachygrams; see `node_ext::TachyonNode::build_block_tachystamp`.
- Enforces anchor recency and validates the aggregated recursion proof in `validate_tachystamp` during block acceptance.


Data model
----------
- `PcdState { anchor_height, state_commitment, mmr_root, nullifier_root, block_hash, proof, ... }`
- `PcdTransition { prev_state_commitment, new_state_commitment, mmr_delta, nullifier_delta, block_height_range, transition_proof }`
- Deltas are bincode’d batches from `accum_mmr::MmrDelta` and `accum_set::SetDelta`.
- Proofs are Halo2-based for state transitions (no mocks/stubs).
- `SyncManifest { height, items: Vec<ManifestItem{ kind, cid, size, ticket, height }] }` published per height; contains only public metadata.
 - Node publishes block-derived `CommitmentDelta` and `NullifierDelta`; OSS publishes `PcdTransition` and a `Manifest` referencing the tickets.


Flows
-----
- **Sync**: wallet subscribes to Manifests → fetches per-height deltas/proofs via tickets → applies via `pcd_core` → updates `PcdState` → persists; OSS learns only CIDs/sizes.
- **Chain nullifier observation (optional)**: if `TACHYON_ZEBRA_NULLIFIER_URL` is set, the wallet fetches recent nullifiers, derives NF2 per unspent note, and flags locally-spent notes.
 - **Header import (optional)**: if `TACHYON_ZEBRA_HEADERS_URL` is set, header sync fetches raw headers via Zebra HTTP first, then falls back.
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
 - `TACHYON_ZEBRA_HEADERS_URL`: optional Zebra headers base URL (enables header import before peer requests).
- `TACHYON_ALLOW_INSECURE=1`: allow localhost endpoints and default password for dev.

Halo2 parameters (global)
-------------------------
- `TACHYON_PCD_KEYS_DIR`: directory for Halo2 params/meta (default `crates/node_ext/node_data/keys`).
- `TACHYON_PCD_K`: circuit size exponent (default `12`).
The crates load these via a common helper so CI and production can override.

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

- Tachystamps (no wallet; quick prototyping)
  - Build from hex (comma-separated grams; repeat `--action` for pairs):
    - `cargo run -p cli -- tachy-build-stamp --height 123 --mmr 0x1111... --nulls 0x2222... --grams 0xaaaa...,0xbbbb... --action 0xaaaa... 0xbbbb...`
  - Verify a JSON stamp (stdin or file):
    - `cargo run -p cli -- tachy-verify-stamp --file ./stamp.json`

- Network
  - Start node: `cargo run -p cli -- network node --data-dir ./tachyon_data --listen-addr 0.0.0.0:8080 [--bootstrap-nodes a,b]`
  - Publish blob: `cargo run -p cli -- network publish --file ./blob.bin --kind pcd_transition --height 42`


Assumptions & non-goals
-----------------------
- Fixed demo keys, localhost relay, permissive defaults; safe for local dev only.
- Transition proofs are real Halo2; performance numbers are still aspirational.
- Ingress limits: bounded mpsc channels and per-peer token-bucket limiting on control ingress.
- Shared HTTP pooling: `tachyon_common::HTTP_CLIENT` for connection reuse across crates.
- OSS auth/rate limit is minimal.
- API surfaces may change.


Build & run
-----------
- Build: `cargo build` (or `--release`)
- Bench: `cargo run -p bench --release`

CI
--
See `.github/workflows/ci.yml` for lint, build, unit tests, and an integration job that:
- Runs `pcd_core` and `circuits` tests (real Halo2 proofs),
- Publishes a header blob locally and runs `oss_service` and `wallet` tests,
- Exports `TACHYON_PCD_KEYS_DIR`/`TACHYON_PCD_K` for reproducible Halo2 setup.


Credits
-------
Idea inspired by Tachyon and Sean Bowe’s writing.

## DEX (orderbook + wallet integration)

A simple in-memory price-time priority orderbook with a pluggable engine and tight wallet integration for balances and settlement.

- Engine
  - In-memory `DexService` by default; optional `sled`-backed engine.
  - Automatic snapshot persistence for the in-memory engine at `<wallet_db>/dex/orderbook.bin` (loaded on startup, saved after order ops).
  - Single market (BASE/USDC) for now; integer `u64` prices/qty.

- Wallet integration
  - Uses `storage::TokenLedger` with available/locked balances.
  - Bids lock USDC; asks lock BASE. Fills are settled atomically:
    - Bid fill: spend locked USDC, credit BASE.
    - Ask fill: spend locked BASE, credit USDC.
  - Market orders refund any unused locks; cancel unlocks remaining.

- CLI usage (examples)

```bash
# Show balances
cargo run -p cli -- dex balance --db-path ~/.tachyon/wallets/alice --password pass

# Deposit demo funds
cargo run -p cli -- dex deposit-usdc --db-path ~/.tachyon/wallets/alice --amount 1000000 --password pass
cargo run -p cli -- dex deposit-base --db-path ~/.tachyon/wallets/alice --amount 25 --password pass

# Place orders
cargo run -p cli -- dex place-limit --db-path ~/.tachyon/wallets/alice --side bid --price 100 --qty 10 --password pass
cargo run -p cli -- dex place-market --db-path ~/.tachyon/wallets/alice --side ask --qty 5 --password pass

# Inspect orderbook and trades
cargo run -p cli -- dex orderbook --db-path ~/.tachyon/wallets/alice --depth 10 --format json --password pass
cargo run -p cli -- dex trades --db-path ~/.tachyon/wallets/alice --limit 20 --password pass

# Watch (polling)
cargo run -p cli -- dex watch --db-path ~/.tachyon/wallets/alice --depth 10 --interval-ms 1000 --password pass
```

Notes: demo-only, no fees or risk controls yet; owner identity is per-wallet and persisted.

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


