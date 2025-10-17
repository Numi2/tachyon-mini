// src/wallet.rs
//! PCD wallet prototype following Tachyon/Ragu objectives.
//!
//! - Unified 32-byte objects (tachy-objects) for commitments and nullifiers.
//! - Split accumulation with linear-domain separation.
//! - Recursive "state proof" carried by the wallet.
//! - Non-uniform synthesis path via metadata parity branch.

use crate::{
    accum::{Accumulator, SplitAccumulator},
    driver::{Circuit, CpuDriver, Driver},
    pasta::{FromBytesWide, FrVesta},
    pcd::{prove_step, verify_step, Pcd, PcdData, RecursionBackend, TranscriptBackend},
};
use blake3::{hash, keyed_hash};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};

/// Unified 32-byte object (tachygram/tachystamp).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TachyObj(pub [u8; 32]);

impl TachyObj {
    #[inline]
    pub fn from_bytes(b: [u8; 32]) -> Self { TachyObj(b) }

    #[inline]
    pub fn to_field(&self) -> FrVesta {
        // 64 bytes via H(x) || H(H(x)) for wide reduction.
        let h1 = hash(&self.0);
        let h2 = hash(h1.as_bytes());
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(h1.as_bytes());
        wide[32..].copy_from_slice(h2.as_bytes());
        FrVesta::from_bytes_wide(&wide)
    }
}

/// Wallet parameters affecting accumulation and metadata.
#[derive(Clone, Debug)]
pub struct WalletParams {
    pub alpha_commit: FrVesta,
    pub alpha_null: FrVesta,
}

impl Default for WalletParams {
    fn default() -> Self {
        fn alpha(label: &[u8]) -> FrVesta {
            let h1 = hash(label);
            let h2 = hash(h1.as_bytes());
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(h1.as_bytes());
            wide[32..].copy_from_slice(h2.as_bytes());
            FrVesta::from_bytes_wide(&wide)
        }
        Self { alpha_commit: alpha(b"ragu-wallet:alpha/commit"), alpha_null: alpha(b"ragu-wallet:alpha/null") }
    }
}

/// A received note tracked by the wallet.
#[derive(Clone, Debug)]
pub struct Note {
    pub commitment: TachyObj,
    pub value: u64,
    pub rseed: [u8; 32],
}

impl Note {
    /// Toy commitment. Real Orchard uses Pedersen+Poseidon; here we use BLAKE3.
    pub fn commit(addr: &TachyObj, value: u64, rseed: [u8; 32]) -> TachyObj {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&value.to_le_bytes());
        let bytes = [addr.0.as_slice(), &buf, &rseed].concat();
        TachyObj(*hash(&bytes).as_bytes())
    }
}

/// Pending batch to incorporate.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub commitments: Vec<TachyObj>,
    pub nullifiers: Vec<TachyObj>,
    /// Optional external metadata; if None we derive it from the batch.
    pub metadata_hint: Option<[u8; 32]>,
}

impl Batch {
    pub fn is_empty(&self) -> bool { self.commitments.is_empty() && self.nullifiers.is_empty() }

    pub fn derive_metadata_bytes(&self) -> [u8; 32] {
        if let Some(m) = self.metadata_hint { return m; }
        // Domain-separated digest: counts || first || last
        let mut counts = [0u8; 16];
        counts[..8].copy_from_slice(&(self.commitments.len() as u64).to_le_bytes());
        counts[8..].copy_from_slice(&(self.nullifiers.len() as u64).to_le_bytes());
        let first_c = self.commitments.first().copied().unwrap_or(TachyObj([0u8; 32]));
        let last_n  = self.nullifiers.last().copied().unwrap_or(TachyObj([0u8; 32]));
        *hash(&[b"ragu-wallet:meta", &counts, &first_c.0, &last_n.0].concat()).as_bytes()
    }

    pub fn fold_accumulator(&self, p: &WalletParams) -> FrVesta {
        let mut acc = SplitAccumulator::<FrVesta>::new();

        for c in &self.commitments {
            let term = p.alpha_commit * c.to_field();
            acc.push(Accumulator::unit(term));
        }
        for n in &self.nullifiers {
            let term = p.alpha_null * n.to_field();
            acc.push(Accumulator::unit(term));
        }

        acc.split_fold().v
    }
}

/// Derive a nullifier using a secret spend key and a commitment.
pub fn derive_nullifier(spend_key: &[u8; 32], commitment: &TachyObj) -> TachyObj {
    TachyObj(*keyed_hash(spend_key, &commitment.0).as_bytes())
}

/// Wallet that carries its own recursive state proof.
pub struct Wallet<B: RecursionBackend<FrVesta> = TranscriptBackend> {
    params: WalletParams,
    backend: B,
    pub spend_key: [u8; 32],

    // State tracked locally.
    pub root: FrVesta,
    pub notes: BTreeMap<[u8; 32], Note>,
    pub spent: BTreeSet<[u8; 32]>,

    // The current recursive proof of spendability/history.
    pub pcd: Option<Pcd<FrVesta, B::Proof>>,
}

impl<B: RecursionBackend<FrVesta> + Default> Wallet<B> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        Self {
            params: WalletParams::default(),
            backend: B::default(),
            spend_key: sk,
            root: FrVesta::ZERO,
            notes: BTreeMap::new(),
            spent: BTreeSet::new(),
            pcd: None,
        }
    }

    pub fn address(&self) -> TachyObj {
        // Toy "address" = H(spend_key)
        TachyObj(*hash(&self.spend_key).as_bytes())
    }

    pub fn receive(&mut self, note: Note) {
        self.notes.insert(note.commitment.0, note);
    }

    pub fn spend(&mut self, commitment: &TachyObj) -> TachyObj {
        let nf = derive_nullifier(&self.spend_key, commitment);
        self.spent.insert(commitment.0);
        nf
    }

    /// Apply a batch of public updates and produce a new recursive state proof.
    /// Contract: new_root = old_root + meta * fold_accumulator(batch)
    pub fn apply_batch_and_prove(&mut self, batch: &Batch) -> Pcd<FrVesta, B::Proof> {
        let meta_bytes = batch.derive_metadata_bytes();
        let mut wide = [0u8; 64];
        let m1 = hash(&meta_bytes);
        let m2 = hash(m1.as_bytes());
        wide[..32].copy_from_slice(m1.as_bytes());
        wide[32..].copy_from_slice(m2.as_bytes());
        let meta = FrVesta::from_bytes_wide(&wide);

        let folded = batch.fold_accumulator(&self.params);
        let old = self.root;
        let new = old + meta * folded;

        let data = PcdData { old_root: old, new_root: new, metadata: meta, accumulator: folded };

        let circuit = WalletCircuit;
        let driver = CpuDriver::<FrVesta>::new();

        let p = prove_step(&self.backend, &circuit, driver, self.pcd.as_ref(), data).expect("prove step");
        self.root = new;
        self.pcd = Some(p.clone());
        p
    }

    pub fn verify_latest(&self) -> bool {
        match &self.pcd {
            None => true,
            Some(p) => verify_step(&self.backend, p).is_ok(),
        }
    }
}

/// Non-uniform path: branch on metadata parity (LSB).  Numan
pub struct WalletCircuit;

impl Circuit<FrVesta> for WalletCircuit {
    type Input = PcdData<FrVesta>;
    type Output = ();

    fn synthesize<D: Driver<FrVesta>>(&self, d: &mut D, input: Self::Input) -> Self::Output {
        let lsb_even = (input.metadata.to_repr().as_ref()[0] & 1) == 0;
        if lsb_even {
            // Add a cheap extra relation: accumulator * 1 - accumulator = 0
            let acc = d.input_public(input.accumulator);
            let one = d.add_const(acc, FrVesta::ONE); // alloc a value to keep it in-circuit
            let _tmp = d.mul(acc, one); // not enforced further; we just exercise different path
        } else {
            // Alternate path: enforce_zero on (accumulator - accumulator) = 0 - math intuition
            let acc = d.input_public(input.accumulator);
            d.enforce_zero(crate::cs::LinComb::from_var(acc).add_term(acc, -FrVesta::ONE));
        }
    }
}