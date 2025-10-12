Mini Tachyon experiments with a Zcash upgrade path where recursive proofs keep both validators and wallets light without sacrificing privacy.

### How succinctness emerges
- Wallets treat their entire local state as proof-carrying data: each time they absorb a block they roll forward a recursive proof that “everything so far is valid.” When they later spend, that proof (the tachystamp) accompanies the transaction, so validators only need to check the latest step plus the recursive proof rather than replaying history.  
- Because the proof certifies continuity from a recent anchor, nodes can discard older state: validity is compressed into the proof chain instead of needing historical blocks.

### Role of tachystamps and aggregation
- A tachystamp bundles the recursive SNARK, the current anchor, and the relevant nullifier/commitment set (tachygrams). Multiple tachystamps can merge into one, letting a block point to a single proof that attests to many prior state transitions.  
- Aggregation keeps verification work small: instead of dozens of membership and nullifier proofs, validators check one recursive SNARK whose statement captures them all.

### Oblivious sync and privacy
- Wallet note retrieval shifts off-chain. An oblivious sync service fetches encrypted updates and helps build the recursive proof without learning secrets.  
- Adjusted nullifier formats (“flavors”) keep the service from linking spends or inferring balances, preserving the indistinguishability of shielded transactions even though syncing happens through an untrusted helper.

### Resulting workflow (simplified)
1. Wallet sits at an anchor (checkpoint with proof).  
2. Each new block updates wallet state and extends the PCD proof.  
3. When spending, the wallet attaches the tachystamp plus a fresh proof for the new action.  
4. Validators verify that combined proof and the latest nullifier checks.  
5. Historic blocks can be pruned—validators rely on the recursive proof chain instead.

### Cryptographic grounding
- Halo-style recursion (no trusted setup) makes the continual proof folding feasible.  
- Prior work on PCD and proof aggregation underpins Tachyon’s design choices.  
- Zcash primitives (nullifiers, commitments) are simplified to fit recursion smoothly.

Net effect: succinct chain validation, lightweight wallet sync, and preserved shielded privacy all ride on recursive proofs that carry the full history’s correctness in a single object.