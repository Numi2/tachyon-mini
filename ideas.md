**Diagram: Tachyon data and proof flow**

```
┌──────────────────────────────────────────────┐
│                   WALLET                     │
│----------------------------------------------│
│ Create note → commitment (Poseidon hash)     │
│ Derive nullifier = PRFspend(note)            │
│ Generate proof of spend (recursive SNARK)    │
│ Produce tachystamp = {tachygrams, anchor ID, │
│                      proof}                  │
│ Send tx to oblivious sync service            │
└──────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│         OBLIVIOUS SYNCING SERVICE            │
│----------------------------------------------│
│ Updates wallet PCD chain off-device          │
│ Uses validator state hash chain anchor       │
│ Returns next proof + updated state           │
└──────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│                VALIDATORS                    │
│----------------------------------------------│
│ Maintain hash chain of vector commitments    │
│ (Poseidon-based) for recent accumulator      │
│ Verify tachystamp proofs                    │
│ Aggregate proofs per block (recursive)       │
│ Append new hash to chain                    │
└──────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│                ACCUMULATOR                   │
│----------------------------------------------│
│ Holds all tachygrams (commitments+nullifiers)│
│ Membership & non-membership proofs           │
│ Anchors identify valid range                 │
└──────────────────────────────────────────────┘
```

**Simplified proof-data feedback loop**

```
Wallet ↔ Sync Service ↔ Validator ↔ Accumulator
        ▲                 │
        └── Recursive proofs (PCD) ◄───────────┘
```

---

**Technology stack (assuming Poseidon as default hash)**

| Component              | Technology                                  | Purpose                                         |
| ---------------------- | ------------------------------------------- | ----------------------------------------------- |
| **Language**           | Rust                                        | All core proving and wallet logic               |
| **PCD engine**         | `ragu`                                      | Recursive SNARK generation and aggregation      |
| **Curves**             | Pasta cycle (Pallas/Vesta)                  | Native field arithmetic for proofs              |
| **Hash function**      | Poseidon                                    | Hashes, PRFs, and vector commitments            |
| **Accumulator**        | Universal accumulator (Poseidon-based)      | Membership/non-membership proofs for tachygrams |
| **State commitments**  | Hash chain of vector commitments            | Validator state anchoring                       |
| **Nullifier function** | Poseidon-keyed PRF                          | Prevents double-spends                          |
| **Commitments**        | Homomorphic Pedersen-like (Poseidon inside) | Value and note commitments                      |
| **Signatures**         | RedPallas                                   | Binding authorization and key randomization     |
| **Serialization**      | Canonical binary format                     | Cross-wallet consistency                        |
| **Networking**         | Mixnets + store-and-forward                 | Privacy of sync and payment requests            |
| **Aggregation logic**  | Shielded transaction aggregates             | Batch proofs and compress chain verification    |
| **Deployment**         | Orchard upgrade or new pool via turnstile   | Integration path to Zcash consensus             |

Hash chains replace Merkle trees as validator commitments. Recursive PCD proofs tie everything together.
