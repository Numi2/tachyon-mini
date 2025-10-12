Mini Tachyon experiments with a Zcash upgrade path where recursive proofs keep both validators and wallets light without sacrificing privacy.


Dependency graph of Tachyon concepts from Sean Bowe’s blog posts:

                         ┌────────────────────┐
                         │  Core Goals        │
                         │ O(1) chain growth  │
                         │ Fast wallet sync   │
                         │ Privacy preserved  │
                         └─────────┬──────────┘
                                   │
                ┌──────────────────┴───────────────────┐
                │                                      │
     ┌──────────▼─────────┐                  ┌─────────▼─────────┐
     │ Oblivious Sync     │                  │ Out-of-Band Txns  │
     │ - PCD proofs       │                  │ - no in-band      │
     │ - recursive SNARKs │                  │   ciphertexts     │
     └──────────┬─────────┘                  │ - URIs/payment    │
                │                            │   requests        │
                │                            └─────────┬─────────┘
                │                                      │
     ┌──────────▼──────────┐                  ┌─────────▼─────────┐
     │ Tachystamps (PCD)   │                  │ Simplified Wallet │
     │ - wrap tachygrams   │                  │ - no diversifiers │
     │ - carry history     │                  │ - leaner circuits │
     └──────────┬──────────┘                  └─────────┬─────────┘
                │                                      │
                │                                      │
     ┌──────────▼─────────┐                 ┌──────────▼──────────┐
     │ Tachygrams         │                 │ Nullifier Derivation │
     │ - unified blob     │                 │ - keyed PRF          │
     │   (commit+null)    │                 │ - pruning enabled    │
     └──────────┬─────────┘                 └──────────┬──────────┘
                │                                      │
                └──────────────┬───────────────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ Accumulators & Proofs   │
                  │ - one set for both      │
                  │ - batch inserts         │
                  │ - membership + non-mem  │
                  └────────────┬────────────┘
                               │
                  ┌────────────▼────────────┐
                  │ Aggregated Blocks       │
                  │ - producers merge       │
                  │   tachystamps           │
                  │ - constant verification │
                  └─────────────────────────┘

Flow:
	1.	Core goals drive two design tracks: Oblivious sync (proof-carrying data) and Out-of-band transactions (no ciphertexts in chain).
	2.	Oblivious sync → Tachystamps (recursive envelopes).
	3.	Out-of-band → simpler wallet + unified tachygrams + new nullifier rules.
	4.	Tachygrams + nullifier changes feed into accumulators.
	5.	Accumulators + tachystamps → aggregated block proofs.


- Wallets treat their entire local state as proof-carrying data: each time they absorb a block they roll forward a recursive proof that “everything so far is valid.” When they later spend, that proof (the tachystamp) accompanies the transaction, so validators only need to check the latest step plus the recursive proof rather than replaying history.  

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

