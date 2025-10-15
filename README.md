Tachyon-mini: credit to Sean Bowe and Zcash team, ideas from Sean Bowe Blog
===============================================================

Overview
--------
Tachyon-mini is a Rust workspace prototyping a succinct, privacy-preserving ledger that follows the Tachyon plan: a unified tachygram accumulator with per-block proofs and wallet-side range non-membership proofs, all on Pasta curves with Halo2/IPA recursion.

What’s implemented
------------------
- Pasta orientation: Vesta circuit field (Fr), Pallas G1 commitment group (no pairings)
- Tachygrams: indistinguishable 32-byte tags for commitments/nullifiers
- Polynomial publisher (per block):
  - Build p_i(X)=∏(X−a_{ij}) for that block’s tachygrams
  - Commit to coeffs in a Pallas PCS domain and SNARK the evaluation p_i(r)=∏(r−a_{ij}) in a Vesta-field Halo2 circuit
  - Publish (P_i, h_i, A_{i+1}, proof) where h_i=H_A(A_i,P_i) and A_{i+1}=[h_i]A_i+P_i
- Wallet IVC (range non-membership):
  - For a secret tag v, compute α_i=p_i(v) and prove α_i≠0 via an inverse witness β_i with α_i·β_i=1
  - Maintain S_{i+1}=[h_i’]S_i+P_i’ with P_i’=P_i−[α_i]G_0 and h_i’=H_S(S_i,P_i’)
  - Final proof shows A_m matches the chain’s accumulator and S_m(v)=0 over the chosen range
- Recursive aggregation (Halo2/IPA) for O(1) verification

Key crates and files
--------------------
- circuits
  - pcs.rs: Pallas PCS helpers (generators, Horner eval, product-of-differences, FS/domain hashes)
  - unified_block.rs: PolyPublisherCircuit + helpers (prove/verify)
  - wallet_step.rs: Wallet IVC step (prove/verify α_i≠0 and S update)
- node_ext: publisher integration wiring in block production
- wallet: hooks for wallet-side IVC and state management
- cli: demo commands to prove/verify publisher and wallet steps

Quick start
-----------
- Build all crates:
```bash
cargo build
```

- Run core tests (optional):
```bash
cargo test -p circuits -p node_ext -p wallet -- --nocapture
```

CLI demos (small bounds)
------------------------
- Prove a polynomial publisher instance (demo bounds MAX_DEG=8, MAX_ROOTS=8):
```bash
cargo run -p cli -- PolyPublisherProve \
  --k 12 --a-i 7 --p-i 11 --a-next 11 --h-i 1 \
  --coeffs 1,2,3 --roots 4,5 --block-len 2
```
Use the returned 0x-hex to verify:
```bash
cargo run -p cli -- PolyPublisherVerify \
  --k 12 --a-i 7 --p-i 11 --a-next 11 --h-i 1 \
  --block-len 2 --proof-hex 0x...
```

- Prove a wallet IVC step (demo bounds MAX_ROOTS=8):
```bash
cargo run -p cli -- WalletStepProve \
  --k 12 --a-i 1 --s-i 0 --p-i 2 --a-next 3 --s-next 4 \
  --v 9 --roots 3,5,7 --flags 1,1,0 --beta 1
```
Verify with:
```bash
cargo run -p cli -- WalletStepVerify \
  --k 12 --a-i 1 --s-i 0 --p-i 2 --a-next 3 --s-next 4 \
  --proof-hex 0x...
```

Design notes
------------
- Pasta cycle: Pallas (commitment group), Vesta (circuit field)
- Hashing: Poseidon2 (t=3, rate=2) with explicit domain tags for H_A/H_S and FS
- Consensus surface: a single Halo2 proof per block attesting to the published (P_i, h_i, A_{i+1})
- Wallet range proofs: constant-size per block with IVC and private role selection

Credits
-------
Tachyon, Zcash, and especially Sean Bowe’s writings inspired this prototype.