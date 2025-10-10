

	1.	Wallet (client, PCD machine)
– Holds notes, secrets, proofs.
– Syncs via iroh/OSS.
– Builds spends that include PCD.
– PQ secure out-of-band payment handling.
	2.	Oblivious Sync Service (OSS)
– Heavy lifting for wallet sync.
– Publishes deltas and transition proofs as blobs.
– Wallets can be light.
	3.	Node / Validator extension
– Minimal state.
– Verifies PCD proofs and spends.car
– Maintains short nullifier window.
– Prunes history.
	4.	Accumulator service / delta generator
– Produces commitment and nullifier updates.
– Feeds OSS and nodes.
	5.	Header sync
– Lets new participants join quickly without replaying all history.

 prototype Tachyon network:
	•	Wallet software (with PCD logic).
	•	Node software (with validator + pruning).
	•	OSS (sync servers for wallets).
	•	Shared accumulator + header sync layer (protocol substrate).

---
Design Goals
	•	Wallets maintain proof-carrying state (PCD) to avoid heavy sync work by validators.
	•	Validators store minimal live state, prune all old state.
	•	Oblivious sync service (OSS) advances wallet state without learning secrets.
	•	Networking via iroh / iroh-blobs content-addressed transfer.
	•	PQ-ready for out-of-band secret distribution.
	•	High performance, secure, maintainable.

⸻

Key Technology Choices
	•	Networking / transport / content addressing:
  Use iroh + iroh-blobs as core network and data transport. Iroh offers P2P QUIC with hole punching, relays, NodeId-based dialing.  ￼
  iroh-blobs offers BLAKE3-verified streaming of blobs and chunk-level integrity.  ￼
	•	Hashing / content addressing: BLAKE3 with the hazmat API for subtree hashing.  ￼
	•	Zero-knowledge / proofs: halo2 (recursive where needed).
	•	Accumulators / state: MMR-based or similar append-only accumulator, optimized for batched updates and proof deltas.
	•	Storage: hybrid – small blobs inline in embedded store; large blobs stored as files with outboard tree. (iroh-blobs follows this model)  ￼
	•	Async runtime: Tokio (compatible with iroh).
	•	PQ cryptography: use a standard KEM like Kyber for out-of-band payload confidentiality.
	•	Serialization / RPC control: use custom framed messages (e.g. via Prost) over an iroh stream; blobs handled by the content-addressed layer (not RPC).
	•	Concurrency model / IO model: isolate blocking IO (e.g. file writes, DB) into worker threads, async facade to main runtime (pattern used in iroh).  ￼

⸻

System Components & Interfaces

Components
	1.	Wallet (client)
  Maintains local encrypted note database, inclusion witnesses, PCD state and recursive proof.
  Talks to OSS via control stream, fetches blob data via iroh-blobs.
	2.	Oblivious Sync Service (OSS)
  Publishes deltas + PCD transitions as blobs; serves fetches; speaks control protocol.
	3.	Accumulator backend / Delta generator
  Computes note-commitment / nullifier MMR deltas per block. Exports blobs.
	4.	Validator / Node extension
  Verifies transaction-level PCD and nullifier checks in recent window. Prunes old data.
	5.	Header chain / checkpoint sync
  Uses NiPoPoW or skip-sync model to allow fast bootstrapping of headers.

⸻

Network / Data Flow using iroh / iroh-blobs
	•	All state deltas, PCD transition proofs, parameter blobs are stored and addressed via iroh-blobs.
	•	OSS and node publish blobs (commitments, nullifiers, transitions) into their blob stores and announce their BLAKE3 hash (CID).
	•	Wallet subscribes or receives announcements, fetches blobs via iroh-blobs (streaming, verifiable).
	•	Control messages (announce, requests, responses) go over a separate iroh stream (ALPN for control).
	•	Blobs may be chunked (≤ 16 KiB groups, or per iroh-blobs strategy) with outboard proofs for integrity.  ￼

⸻

Protocol Outline

Out-of-band Payment (OOB)
	•	Sender uses PQ KEM (e.g. Kyber) to encapsulate a shared secret to recipient’s public key.
	•	Use that secret to AEAD-encrypt the note metadata (view key, randomness, etc.).
	•	On-chain, only the note commitment and public data are published.
	•	Recipient decapsulates and recovers the note secret.
	•	This approach ensures on-chain does not leak note secrets and is PQ resistant for that part.

Wallet State and PCD Evolution
	•	Wallet holds:
  • Encrypted note records
  • Witness paths in MMR
  • Current PCD proof / state commitment
  • Anchor (height) at which PCD is valid
	•	For each new block (or batch of blocks):
  • Wallet requests from OSS the delta blobs (commitment delta, nullifier delta) and PCD transition blob(s).
  • Fetch via iroh-blobs, verify hash, pass to MMR module to update witnesses.
  • Supply these deltas + previous PCD state to a transition circuit that outputs new PCD + proof.
  • Optionally, fold recursive proofs to bound proof size.
	•	Wallet can fallback to local proving if OSS unreachable (higher cost).

Spending / Transaction Construction
	•	Wallet picks notes, constructs standard shielded spend (Orchard-like).
	•	Attach PCD proof that wallet state is valid up to anchor A.
	•	Reveal nullifiers.
	•	Transaction fields: note spend bundle, PCD proof + state commitment, anchor.
	•	Node checks:
  • PCD proof correctness and consistency with anchor
  • For each nullifier, that it is not in the recent window (sliding window)
  • Validate spend proof (Orchard).

Node / Validator Behavior & Pruning
	•	Nodes maintain recent nullifier window (e.g. last W blocks).
	•	Nodes accept only transactions whose nullifiers do not collide with window.
	•	After safety depth, prune full commitment / nullifier history, keeping only MMR peaks, minimal proofs needed for new sync.
	•	Keep header chain + summary roots needed to verify new blocks and PCD consistency.

OSS Behavior
	•	Tracks block production / delta generator.
	•	Produces:
  • commitment_delta.blob
  • nullifier_delta.blob
  • pcd_transition.blob
  with agreed semantics.
	•	Publishes them via blob store, announces via control stream.
	•	Serves fetch requests automatically via blob protocol.
	•	Enforces rate limits, token-based access, unlinkability of requests.

⸻

Rust Project Structure (workspace)

tachyon-rs/
  crates/
    net_iroh        — wrapper over iroh + iroh-blobs, control stream, blob API  
    accum_mmr        — accumulator, MMR, delta apply, witness updates  
    pcd_core         — state definitions, proof interface, recursion management  
    circuits          — halo2 circuits: transition, aggregation  
    wallet            — wallet logic: note DB, OOB, sync client  
    oss_service       — OSS server logic: delta generation, control logic  
    node_ext          — validator extension: PCD verify, nullifier checks  
    header_sync       — header chain + checkpoint / NiPoPoW logic  
    pq_crypto         — KEM + AEAD interface for OOB  
    storage           — DB layer (embedded store + fallback)  
    cli               — command-line tools  
    bench             — benchmarks & performance tests  

Key trait interfaces:

trait BlobStore {
  fn put_blob(&self, cid: &[u8], data: Bytes) -> Result<()>;
  fn fetch_blob(&self, cid: &[u8]) -> impl Future<Output = Result<Bytes>>;
  fn has_blob(&self, cid: &[u8]) -> bool;
}

trait ControlProtocol {
  fn send_announce(&mut self, kind: BlobKind, cid: Cid, height: u64);
  fn send_request(&mut self, cid: Cid);
  fn recv(&mut self) -> impl Stream<Item = ControlMessage>;
}

trait PcdState {
  fn anchor(&self) -> u64;
  fn state_commitment(&self) -> [u8; 32];  // or appropriate size
  fn proof(&self) -> &[u8];
}

trait Transition {
  fn apply(prev: &PcdState, delta_blobs: &DeltaBundle) -> (PcdState, Proof);
}


⸻

Implementation Phases

Phase 1: Core Networking + Blob Layer
	•	Integrate iroh and iroh-blobs crates.
	•	Create net_iroh crate that:
  • Starts an iroh Endpoint with ALPNs.
  • Accepts control streams and blob protocol.
  • Exposes high-level APIs: publish_blob, subscribe_announcements, fetch_blob.
	•	Build a minimal test: two nodes, node A publishes a blob, node B fetches and verifies via BLAKE3.
	•	Use latest BLAKE3 hazmat API to compute subtrees and chunk proofs.  ￼

Phase 2: Accumulator & MMR
	•	Build accum_mmr crate: append-only structure, proof generation, delta application, witness updates.
	•	Support batched deltas and shared path compression.
	•	Tests: small sets, large sets, path correctness.

Phase 3: PCD Circuits
	•	In circuits, build a transition circuit T that proves:
  • Given previous state commitment, applying deltas yields new state commitment consistent with MMR roots.
  • No double-spend in nullifier delta.
  • Anchor increments correctly.
	•	Build recursion circuit R for proof folding.
	•	In pcd_core, provide prove and verify APIs.

Phase 4: Wallet + OSS
	•	Wallet:
  • OOB interface (PQ KEM + AEAD)
  • Note DB, encrypted store
  • Sync client: connect to OSS via control protocol, fetch blobs, apply transitions via pcd_core
  • Spend builder: combine new PCD proof + note spend circuit
	•	OSS:
  • Accept registration / subscription tokens from wallets
  • Periodically generate block deltas + PCD transitions
  • Publish blobs and send announce messages
  • Serve fetches
  • Manage quotas, access control

Phase 5: Validator / Node Extension
	•	Extend node to validate tx + pcd_blob:
  • Verify PCD, ensure nullifier non-membership in recent window
  • Accept orchard spend proof
  • Append to block
	•	Pruning: discard older states keeping only needed MMR peaks and commitments.

Phase 6: Header Sync & Bootstrapping
	•	Implement NiPoPoW or skip proofs to allow new nodes to bootstrap headers + root commitments.
	•	On boot, wallet can sync from checkpoint + deltas rather than full history.

Phase 7: Hardening, Privacy, PQ Transition Path
	•	Nullifier derivation: include epoch tag / VRF blinding so OSS cannot correlate positions.
	•	Token rotation, request padding, batching.
	•	Fallback local proving if OSS unreachable.
	•	PQ migration path: optional flag to insert PQ signature witness in PCD for on-chain authentication (if protocol upgrade later).

⸻

iroh / iroh-blobs Specific Updates to Use
	•	Use latest iroh (≥0.92) which supports improved mDNS, QUIC multipath, better relay fallback.  ￼
	•	Leverage iroh-blobs (latest) for BLAKE3-verified streaming, range requests, chunked fetching.  ￼
	•	Use BLAKE3’s hazmat API to compute subtree hashes and combine chaining values when validating partial chunks.  ￼
	•	Use a thread-pool + blocking IO separation to handle file storage / DB in iroh-blobs style.  ￼

⸻

Performance & Security Targets
	•	Wallet sync latency: ≤ 100 ms per 10 block batch on moderate connection.
	•	Transition proving: ≤ 100–500 ms for typical delta size (depends on circuit).
	•	Proof size (recursive folded): ≤ 32–64 KiB target.
	•	Validator verification: ≤ few ms per transaction (PCD + spend).
	•	Storage on node: minimal (just MMR peaks + recent window)
	•	Bandwidth overhead: blobs compressed, chunk deduplication, delta grouping.
	•	Security constraints:
  • Soundness of circuits
  • No information leakage in blobs (only reveal deltas, not note secrets)
  • OSS cannot infer note positions (via blinding)
  • Resist DoS (limit blob size, rate-limit access)
  • PQ secrecy in OOB payloads
  • Replay / reorg safety: PCD should support fork rewind and recompute.

