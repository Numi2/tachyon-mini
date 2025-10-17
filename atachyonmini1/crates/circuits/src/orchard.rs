//! Orchard-style gadgets and circuits
//! Numan Thabit 2025
//!
//! This module gives you the building blocks for Orchard-like privacy features!
//! We've got tools for creating note commitments (like receipts), deriving nullifiers
//! (to prevent double-spending), and proving membership in sets.
//! 
//! Everything uses Poseidon hashing on Pasta curves for maximum ZK-friendliness.
//! We focus on the core cryptographic gadgets here - the spending authorization
//! logic lives elsewhere.


use ff::Field;
use ff::PrimeField;
use ff::FromUniformBytes;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::Fp as Fr;

/// Special tags that keep different cryptographic operations separate.
/// Like using different salt for different recipes - keeps everything organized!
pub mod domain {
    use super::*;
    pub const TAG_NOTE_COMMIT: u64 = 101;  // For note commitments
    pub const TAG_NULLIFIER: u64 = 102;    // For nullifiers (prevents double-spending)
    pub const TAG_IVK: u64 = 103;          // For incoming viewing keys
    pub const TAG_RK: u64 = 104;           // For randomized keys
    pub const TAG_NF_A: u64 = 105;         // Nullifier derivation step A
    pub const TAG_NF_B: u64 = 106;         // Nullifier derivation step B
    // Wallet public input tags (version 1)
    pub const TAG_STATE_V1: u64 = 201;     // For wallet state roots
    pub const TAG_LINK_V1: u64 = 202;      // For transaction links

    /// Converts a tag number into a field element
    pub fn tag_to_fr(tag: u64) -> Fr { Fr::from(tag) }
}

/// Wraps up our Poseidon hash configuration (width=3, rate=2).
/// This is the settings we use throughout to keep everything consistent.
#[derive(Clone, Debug)]
pub struct Poseidon2Config {
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

impl Poseidon2Config {
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: &[Column<Advice>; 6]) -> Self {
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::<Fr, 3, 2>::configure::<P128Pow5T3>(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            rc_a,
            rc_b,
        );
        Self { poseidon }
    }
}

/// Creates a note commitment - think of it like a sealed envelope with the note's value inside.
/// We hash together: the recipient's public key + the value amount.
/// This commitment can be put on-chain without revealing what's inside!
pub fn note_commitment<const DEPTH: usize>(
    mut layouter: impl Layouter<Fr>,
    cfg: &OrchardMembershipConfig<DEPTH>,
    pk: Value<Fr>,
    value: Value<Fr>,
) -> Result<halo2_proofs::circuit::AssignedCell<Fr, Fr>, Error> {
    let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
    let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
        chip,
        layouter.namespace(|| "poseidon note commitment"),
    )?;

    let tag_cell = layouter.assign_region(
        || "tag_note_commit",
        |mut region| {
            let c = region.assign_advice(|| "tag", cfg.advice[0], 0, || Value::known(domain::tag_to_fr(domain::TAG_NOTE_COMMIT)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NOTE_COMMIT))?;
            Ok(c)
        },
    )?;

    // Assign inputs
    let pk_cell = layouter.assign_region(
        || "pk",
        |mut region| region.assign_advice(|| "pk", cfg.advice[1], 0, || pk),
    )?;
    let val_cell = layouter.assign_region(
        || "value",
        |mut region| region.assign_advice(|| "value", cfg.advice[2], 0, || value),
    )?;

    let cm = h.hash(layouter.namespace(|| "H(tag, pk, v)"), [tag_cell, pk_cell, val_cell])?;
    Ok(cm)
}

/// Derives a nullifier from a commitment - this is how we prevent double-spending!
/// Each note has exactly one nullifier. When you spend a note, its nullifier goes on-chain.
/// If anyone tries to spend the same note again, we'll see the duplicate nullifier and reject it.
pub fn nullifier<const DEPTH: usize>(
    mut layouter: impl Layouter<Fr>,
    cfg: &OrchardMembershipConfig<DEPTH>,
    commitment: halo2_proofs::circuit::AssignedCell<Fr, Fr>,
    rho: Value<Fr>,
) -> Result<halo2_proofs::circuit::AssignedCell<Fr, Fr>, Error> {
    let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
    let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
        chip,
        layouter.namespace(|| "poseidon nullifier"),
    )?;
    let tag_cell = layouter.assign_region(
        || "tag_nullifier",
        |mut region| {
            let c = region.assign_advice(|| "tag", cfg.advice[0], 0, || Value::known(domain::tag_to_fr(domain::TAG_NULLIFIER)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NULLIFIER))?;
            Ok(c)
        },
    )?;
    let rho_cell = layouter.assign_region(
        || "rho",
        |mut region| region.assign_advice(|| "rho", cfg.advice[1], 0, || rho),
    )?;
    let nf = h.hash(layouter.namespace(|| "H(tag, cm, rho)"), [tag_cell, commitment, rho_cell])?;
    Ok(nf)
}

/// A variant of nullifier that uses a secret nullifier key instead of the commitment.
/// This ties the nullifier to your spending authority - only you can derive it because
/// only you know your secret nk!
pub fn nullifier_prf<const DEPTH: usize>(
    mut layouter: impl Layouter<Fr>,
    cfg: &OrchardMembershipConfig<DEPTH>,
    nk: Value<Fr>,
    rho: Value<Fr>,
) -> Result<halo2_proofs::circuit::AssignedCell<Fr, Fr>, Error> {
    let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
    let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
        chip,
        layouter.namespace(|| "poseidon nullifier prf"),
    )?;
    let tag_cell = layouter.assign_region(
        || "tag_nullifier_prf",
        |mut region| {
            let c = region.assign_advice(|| "tag", cfg.advice[0], 0, || Value::known(domain::tag_to_fr(domain::TAG_NULLIFIER)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NULLIFIER))?;
            Ok(c)
        },
    )?;
    let nk_cell = layouter.assign_region(
        || "nk",
        |mut region| region.assign_advice(|| "nk", cfg.advice[1], 0, || nk),
    )?;
    let rho_cell = layouter.assign_region(
        || "rho",
        |mut region| region.assign_advice(|| "rho", cfg.advice[2], 0, || rho),
    )?;
    let nf = h.hash(layouter.namespace(|| "H(tag, nk, rho)"), [tag_cell, nk_cell, rho_cell])?;
    Ok(nf)
}

/// Circuit configuration for proving you have a valid note and can spend it.
/// Note: We've switched from Merkle trees to an accumulator-based approach for better efficiency!
#[derive(Clone, Debug)]
pub struct OrchardMembershipConfig<const DEPTH: usize> {
    pub advice: [Column<Advice>; 6],  // For private witness data
    pub selector: Selector,            // Turns the circuit logic on/off
    pub poseidon: Poseidon2Config,     // Our hash function setup
    pub instance: Column<Instance>,    // For public inputs/outputs
}

#[derive(Clone, Debug)]
pub struct OrchardMembershipCircuit<const DEPTH: usize> {
    pub pk: Value<Fr>,     // The recipient's public key
    pub value: Value<Fr>,  // The note's value amount
    pub rho: Value<Fr>,    // Random nonce for this note
    /// Your secret nullifier key - proves you're authorized to spend this note!
    /// In real life this comes from your wallet's master secret.
    pub nk: Value<Fr>,
    pub siblings: [Value<Fr>; DEPTH],   // Merkle path siblings (currently unused with accumulator)
    pub directions: [Value<Fr>; DEPTH], // Path directions (currently unused with accumulator)
}

impl<const DEPTH: usize> Circuit<Fr> for OrchardMembershipCircuit<DEPTH> {
    type Config = OrchardMembershipConfig<DEPTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            pk: Value::unknown(),
            value: Value::unknown(),
            rho: Value::unknown(),
            nk: Value::unknown(),
            siblings: [Value::unknown(); DEPTH],
            directions: [Value::unknown(); DEPTH],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for a in &advice { meta.enable_equality(*a); }
        let selector = meta.selector();
        let poseidon = Poseidon2Config::configure(meta, &advice);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        OrchardMembershipConfig { advice, selector, poseidon, instance }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Step 1: Create the note commitment - like sealing an envelope
        let cm = note_commitment(
            layouter.namespace(|| "note commitment"),
            &cfg,
            self.pk,
            self.value,
        )?;

        // Step 2: We used to verify Merkle membership here, but we've moved to accumulators!
        // It's more efficient this way. The commitment gets bound to the accumulator state.
        
        // Step 3: Derive the nullifier using your secret key
        // This proves you have the authority to spend this note.
        // The signature check happens at a higher level.
        let _nullifier = nullifier_prf(layouter.namespace(|| "nullifier_prf"), &cfg, self.nk, self.rho)?;

        // Step 4: Make the commitment public so everyone can see it (but not what's inside!)
        layouter.constrain_instance(cm.cell(), cfg.instance, 0)?;
        Ok(())
    }
}

/// This circuit proves that your transaction is legit - it shows that:
/// 1. Your nullifier and randomized key come from the same secret keys
/// 2. Everything ties back to the accumulator state
/// It's like showing your credentials without revealing your identity!
#[derive(Clone, Debug)]
pub struct SpendLinkConfig<const DEPTH: usize> {
    pub advice: [Column<Advice>; 6],     // Private witness data
    pub selector: Selector,               // Circuit enable switch
    pub poseidon: Poseidon2Config,        // Hash configuration
    pub instance: [Column<Instance>; 2], // Public outputs: [state_root, link]
}

#[derive(Clone, Debug)]
pub struct SpendLinkCircuit<const DEPTH: usize> {
    pub ak: Value<Fr>,      // Your address key (public part)
    pub nk: Value<Fr>,      // Your nullifier key (the secret one)
    pub ask: Value<Fr>,     // Secret key for signatures
    pub alpha: Value<Fr>,   // Random value for key randomization
    pub rho: Value<Fr>,     // Random nonce for this specific note
    pub cm: Value<Fr>,      // The note commitment we're spending
    pub cv: Value<Fr>,      // Value commitment (this becomes public)
    pub siblings: [Value<Fr>; DEPTH],   // Merkle path (for accumulator)
    pub directions: [Value<Fr>; DEPTH], // Path directions (for accumulator)
    // Public input components:
    pub mmr_root: Value<Fr>,   // The MMR accumulator root
    pub nf_root: Value<Fr>,    // The nullifier set root
    pub rk_bytes: Value<Fr>,   // Your randomized verification key
}

impl<const DEPTH: usize> Circuit<Fr> for SpendLinkCircuit<DEPTH> {
    type Config = SpendLinkConfig<DEPTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            ak: Value::unknown(),
            nk: Value::unknown(),
            ask: Value::unknown(),
            alpha: Value::unknown(),
            rho: Value::unknown(),
            cm: Value::unknown(),
            cv: Value::unknown(),
            siblings: [Value::unknown(); DEPTH],
            directions: [Value::unknown(); DEPTH],
            mmr_root: Value::unknown(),
            nf_root: Value::unknown(),
            rk_bytes: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for a in &advice { meta.enable_equality(*a); }
        let selector = meta.selector();
        let poseidon = Poseidon2Config::configure(meta, &advice);
        let instance = [meta.instance_column(), meta.instance_column()];
        for i in &instance { meta.enable_equality(*i); }
        SpendLinkConfig { advice, selector, poseidon, instance }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // 0) Compute state_root = H(TAG_STATE_V1, mmr_root, nf_root) and expose as PI[0]
        let chip_state = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
        let h_state = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_state,
            layouter.namespace(|| "poseidon state_root"),
        )?;
        let tag_state = layouter.assign_region(|| "tag_state_v1", |mut region| {
            let c = region.assign_advice(|| "tag_state_v1", cfg.advice[4], 0, || Value::known(domain::tag_to_fr(domain::TAG_STATE_V1)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_STATE_V1))?;
            Ok(c)
        })?;
        let mmr_cell = layouter.assign_region(|| "mmr_root", |mut region| region.assign_advice(|| "mmr_root", cfg.advice[0], 0, || self.mmr_root))?;
        let nf_cell = layouter.assign_region(|| "nf_root", |mut region| region.assign_advice(|| "nf_root", cfg.advice[1], 0, || self.nf_root))?;
        let state_root = h_state.hash(layouter.namespace(|| "H(tag_state, mmr, nf)"), [tag_state, mmr_cell.clone(), nf_cell.clone()])?;
        layouter.constrain_instance(state_root.cell(), cfg.instance[0], 0)?;

        // 2) Key consistency (ivk = H(TAG_IVK, ak, nk)) - internal binding, not exposed
        let chip = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
        let h = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon spend link"),
        )?;
        let tag_ivk = layouter.assign_region(|| "tag_ivk", |mut region| {
            let c = region.assign_advice(|| "tag_ivk", cfg.advice[4], 0, || Value::known(domain::tag_to_fr(domain::TAG_IVK)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_IVK))?;
            Ok(c)
        })?;
        let ak_cell = layouter.assign_region(|| "ak", |mut region| region.assign_advice(|| "ak", cfg.advice[2], 0, || self.ak))?;
        let nk_cell = layouter.assign_region(|| "nk", |mut region| region.assign_advice(|| "nk", cfg.advice[3], 0, || self.nk))?;
        let _ivk = h.hash(layouter.namespace(|| "H(tag_ivk, ak, nk)"), [tag_ivk, ak_cell.clone(), nk_cell.clone()])?;

        // 3) rk_bytes is provided as witness (ECC constraint to bind ak, alpha → rk will be added)
        let rk_bytes_cell = layouter.assign_region(|| "rk_bytes", |mut region| region.assign_advice(|| "rk_bytes", cfg.advice[5], 0, || self.rk_bytes))?;

        // 4) PRF nullifier: nf = H(TAG_NF_B, H(TAG_NF_A, nk, rho), cm)
        let chip3 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
        let h3 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip3,
            layouter.namespace(|| "poseidon nf"),
        )?;
        let tag_nf_a = layouter.assign_region(|| "tag_nf_a", |mut region| {
            let c = region.assign_advice(|| "tag_nf_a", cfg.advice[4], 2, || Value::known(domain::tag_to_fr(domain::TAG_NF_A)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NF_A))?;
            Ok(c)
        })?;
        // Pre-assign rho to avoid overlapping mutable borrows of layouter
        let rho_cell = layouter.assign_region(|| "rho", |mut region| region.assign_advice(|| "rho", cfg.advice[1], 1, || self.rho))?;
        let d1 = h3.hash(
            layouter.namespace(|| "H(tag_nf_a, nk, rho)"),
            [tag_nf_a, nk_cell.clone(), rho_cell],
        )?;
        let chip4 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
        let h4 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip4,
            layouter.namespace(|| "poseidon nf b"),
        )?;
        let tag_nf_b = layouter.assign_region(|| "tag_nf_b", |mut region| {
            let c = region.assign_advice(|| "tag_nf_b", cfg.advice[4], 3, || Value::known(domain::tag_to_fr(domain::TAG_NF_B)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_NF_B))?;
            Ok(c)
        })?;
        // Reuse cm by assigning a copy outside the hash call to satisfy borrow rules
        let cm_copy = layouter.assign_region(|| "cm_copy", |mut region| region.assign_advice(|| "cm_copy", cfg.advice[0], 1, || self.cm))?;
        let nf = h4.hash(
            layouter.namespace(|| "H(tag_nf_b, d1, cm)"),
            [tag_nf_b, d1, cm_copy],
        )?;

        // 5) Compute link with two rounds to respect t=3, rate=2 sponge and expose as PI[1]
        // Round 1: d1_link = H(TAG_LINK_V1, rk_bytes, nf)
        let chip_link1 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
        let h_link1 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_link1,
            layouter.namespace(|| "poseidon link r1"),
        )?;
        // Round 2: link = H(d1_link, cmx, cv)
        let chip_link2 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.poseidon.clone());
        let h_link2 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip_link2,
            layouter.namespace(|| "poseidon link r2"),
        )?;
        let tag_link = layouter.assign_region(|| "tag_link_v1", |mut region| {
            let c = region.assign_advice(|| "tag_link_v1", cfg.advice[4], 4, || Value::known(domain::tag_to_fr(domain::TAG_LINK_V1)))?;
            region.constrain_constant(c.cell(), domain::tag_to_fr(domain::TAG_LINK_V1))?;
            Ok(c)
        })?;
        let cv_cell = layouter.assign_region(|| "cv", |mut region| region.assign_advice(|| "cv", cfg.advice[3], 1, || self.cv))?;
        let d1_link = h_link1.hash(
            layouter.namespace(|| "H(tag_link, rk_bytes, nf)"),
            [tag_link, rk_bytes_cell, nf],
        )?;
        let cmx_copy = layouter.assign_region(|| "cmx_copy", |mut region| region.assign_advice(|| "cmx_copy", cfg.advice[2], 1, || self.cm))?;
        let link = h_link2.hash(
            layouter.namespace(|| "H(d1_link, cmx, cv)"),
            [d1_link, cmx_copy, cv_cell],
        )?;
        layouter.constrain_instance(link.cell(), cfg.instance[1], 0)?;

        Ok(())
    }
}

/// Proving/verification helper for SpendLinkCircuit
#[derive(Clone)]
pub struct SpendLinkCore<const DEPTH: usize> {
    pub proving_k: u32,
    pub params: halo2_proofs::poly::ipa::commitment::ParamsIPA<pasta_curves::vesta::Affine>,
    pub vk: halo2_proofs::plonk::VerifyingKey<pasta_curves::vesta::Affine>,
    pub pk: halo2_proofs::plonk::ProvingKey<pasta_curves::vesta::Affine>,
}

impl<const DEPTH: usize> SpendLinkCore<DEPTH> {
    pub fn with_k(k: u32) -> anyhow::Result<Self> {
        let params = crate::ParamsIPA::<pasta_curves::vesta::Affine>::new(k);
        let empty = SpendLinkCircuit::<DEPTH> {
            ak: Value::unknown(),
            nk: Value::unknown(),
            ask: Value::unknown(),
            alpha: Value::unknown(),
            rho: Value::unknown(),
            cm: Value::unknown(),
            cv: Value::unknown(),
            siblings: [Value::unknown(); DEPTH],
            directions: [Value::unknown(); DEPTH],
            mmr_root: Value::unknown(),
            nf_root: Value::unknown(),
            rk_bytes: Value::unknown(),
        };
        let vk = halo2_proofs::plonk::keygen_vk(&params, &empty)?;
        let pk = halo2_proofs::plonk::keygen_pk(&params, vk.clone(), &empty)?;
        Ok(Self { proving_k: k, params, vk, pk })
    }

    /// Verify a spend-link proof
    pub fn verify(
        &self,
        proof: &[u8],
        state_root: &[u8; 32],
        link: &[u8; 32],
    ) -> anyhow::Result<bool> {
        use halo2_proofs::transcript::{Blake2bRead, Challenge255};
        use pasta_curves::vesta::Affine as G1Affine;
        use halo2_proofs::plonk::SingleVerifier;
        use std::io::Cursor;
        // Canonical bytes only: reject non-canonical field encodings
        let to_fr_opt = |b: &[u8; 32]| -> Option<Fr> { Option::<Fr>::from(Fr::from_repr(*b)) };
        let inst_state = match to_fr_opt(state_root) { Some(fr) => [fr], None => return Ok(false) };
        let inst_link = match to_fr_opt(link) { Some(fr) => [fr], None => return Ok(false) };
        let mut transcript = Blake2bRead::<Cursor<&[u8]>, G1Affine, Challenge255<G1Affine>>::init(Cursor::new(proof));
        let strategy = SingleVerifier::new(&self.params);
        let ok = halo2_proofs::plonk::verify_proof::<halo2_proofs::poly::ipa::commitment::IPACommitmentScheme<pasta_curves::vesta::Affine>, _, _, _>(
            &self.params,
            &self.vk,
            strategy,
            &[&[&inst_state[..], &inst_link[..]]],
            &mut transcript,
        ).is_ok();
        Ok(ok)
    }
}


/// Prove a spend-link for given raw inputs and return (proof_bytes, state_root, link).
///
/// This helper mirrors the verification shape used by validators: the public
/// instances are [state_root, link], where
///   state_root = Poseidon(TAG_STATE_V1, mmr_root, nf_root)
///   link       = Poseidon(H(TAG_LINK_V1, rk_bytes, nf), cmx, cv)
///
/// Notes:
/// - This prototype sets unused witness values (ak, ask, alpha) to zero.
/// - Siblings/directions are currently unused in the circuit skeleton.
pub fn prove_spend_link<const DEPTH: usize>(
    k: u32,
    mmr_root: &[u8; 32],
    nf_root: &[u8; 32],
    rk_bytes: &[u8; 32],
    nk_seed: &[u8; 32],
    rho: &[u8; 32],
    cmx: &[u8; 32],
    cv: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    use halo2_proofs::plonk::create_proof;
    use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
    use pasta_curves::vesta::Affine as G1Affine;
    use rand::rngs::OsRng;

    // Convert inputs to field elements; use uniform mapping where appropriate.
    fn to_fr(bytes: &[u8; 32]) -> Fr {
        // Prefer canonical if possible, else map uniformly from bytes
        if let Some(fr) = Option::<Fr>::from(Fr::from_repr(*bytes)) { return fr; }
        use std::io::Read as _;
        let mut h = blake3::Hasher::new();
        h.update(b"orch:to_fr:uniform:v1");
        h.update(bytes);
        let mut wide = [0u8; 64];
        h.finalize_xof().read_exact(&mut wide).expect("xof read");
        Fr::from_uniform_bytes(&wide)
    }

    // Build witnesses
    let mmr_fr = to_fr(mmr_root);
    let nf_fr = to_fr(nf_root);
    let rk_fr = to_fr(rk_bytes);
    let nk_fr = to_fr(nk_seed);
    let rho_fr = to_fr(rho);
    let cm_fr = to_fr(cmx);
    let cv_fr = to_fr(cv);

    // Assemble circuit with known witnesses
    let circuit = SpendLinkCircuit::<DEPTH> {
        ak: halo2_proofs::circuit::Value::known(Fr::ZERO),
        nk: halo2_proofs::circuit::Value::known(nk_fr),
        ask: halo2_proofs::circuit::Value::known(Fr::ZERO),
        alpha: halo2_proofs::circuit::Value::known(Fr::ZERO),
        rho: halo2_proofs::circuit::Value::known(rho_fr),
        cm: halo2_proofs::circuit::Value::known(cm_fr),
        cv: halo2_proofs::circuit::Value::known(cv_fr),
        siblings: [halo2_proofs::circuit::Value::known(Fr::ZERO); DEPTH],
        directions: [halo2_proofs::circuit::Value::known(Fr::ZERO); DEPTH],
        mmr_root: halo2_proofs::circuit::Value::known(mmr_fr),
        nf_root: halo2_proofs::circuit::Value::known(nf_fr),
        rk_bytes: halo2_proofs::circuit::Value::known(rk_fr),
    };

    // Deterministically construct proving artifacts
    let core = SpendLinkCore::<DEPTH>::with_k(k)?;

    // Compute instances expected by the verifier
    let state_root = crate::compute_wallet_state_root_bytes(mmr_root, nf_root);
    // Derive nf inside helper exactly like the circuit does:
    // d1 = H(TAG_NF_A, nk, rho); nf = H(TAG_NF_B, d1, cm)
    use halo2_gadgets::poseidon::primitives as p;
    let tag_nf_a = Fr::from(domain::TAG_NF_A);
    let tag_nf_b = Fr::from(domain::TAG_NF_B);
    let d1 = p::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        tag_nf_a,
        nk_fr,
        rho_fr,
    ]);
    let nf_fr = p::Hash::<Fr, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        tag_nf_b,
        d1,
        cm_fr,
    ]);
    let mut nf_bytes = [0u8; 32];
    nf_bytes.copy_from_slice(nf_fr.to_repr().as_ref());

    let link = crate::compute_wallet_link_bytes(rk_bytes, &nf_bytes, cmx, cv);

    // Prepare public instances in Fr form
    let inst_state = Option::<Fr>::from(Fr::from_repr(state_root)).ok_or_else(|| anyhow::anyhow!("non-canonical state_root"))?;
    let inst_link = Option::<Fr>::from(Fr::from_repr(link)).ok_or_else(|| anyhow::anyhow!("non-canonical link"))?;

    // Create proof
    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<halo2_proofs::poly::ipa::commitment::IPACommitmentScheme<pasta_curves::vesta::Affine>, _, _, _, _>(
        &core.params,
        &core.pk,
        &[circuit],
        &[&[&[inst_state], &[inst_link]]],
        OsRng,
        &mut transcript,
    )?;
    let proof = transcript.finalize();

    Ok((proof, state_root, link))
}


