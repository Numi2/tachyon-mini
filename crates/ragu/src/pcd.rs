//! PCD scaffolding for non-uniform circuits with folding accumulation.
//! This defines a minimal step interface so Orchard/Tachyon circuits can
//! emit/consume fold digests and accumulator digests.

use ff::Field;

use crate::accum::{AccumDigest, FoldDigest};
use crate::folding::{PoseidonFoldCombiner, fold_many};
use crate::tachygram::Tachygram;
use crate::accum_unified::{update_unified_accum, alloc_private_bit};
use crate::r1cs::{R1csProverDriver, Wire};

/// A PCD proof artifact (opaque to the host). In this crate we keep it abstract
/// and let the concrete backend serialize its own form.
#[derive(Clone, Debug)]
pub struct PcdProof { pub bytes: Vec<u8> }

/// Public output of a PCD step: an accumulator digest and a fold digest.
#[derive(Clone, Debug)]
pub struct PcdOutput { pub accum: AccumDigest, pub fold: FoldDigest }

/// Trait implemented by PCD steps (different circuits per step allowed).
pub trait PcdStep {
    /// Prove one step, consuming zero or more prior fold digests and an accumulator state digest
    /// (caller can re-derive updated accumulator digest from inputs; we pass only digest to avoid large states).
    fn prove(&self, prior_folds: &[FoldDigest], prev_accum: AccumDigest) -> (PcdProof, PcdOutput);

    /// Verify and return public output.
    fn verify(&self, proof: &PcdProof) -> Option<PcdOutput>;
}

/// A simple driver that aggregates multiple PCD step outputs by folding their fold digests.
pub fn aggregate_outputs(outputs: &[PcdOutput], comb: PoseidonFoldCombiner) -> Option<FoldDigest> {
    let digests: Vec<FoldDigest> = outputs.iter().map(|o| o.fold).collect();
    fold_many(&digests, comb)
}

/// Tachystamp envelope: bundles a set of tachygrams and a recursive proof-of-correctness.
#[derive(Clone, Debug)]
pub struct Tachystamp {
    pub grams: Vec<Tachygram>,
    pub proof: PcdProof,
    pub output: PcdOutput,
}

/// A minimal block step skeleton using unified accumulator updates and recursive binding.
/// This is a placeholder for the real Pasta recursion: we emit foreign escape events for
/// (a) unified accumulator update per gram, and (b) a single recursion binder digest.
pub struct BlockStepParams { pub domain_tag: u64 }

pub fn prove_block_step(
    prev_state_root: pasta_curves::Fp,
    grams: &[Tachygram],
    membership_flags: &[bool],
    prev_fold_digest: FoldDigest,
    params: BlockStepParams,
) -> (PcdProof, PcdOutput) {
    assert_eq!(grams.len(), membership_flags.len());
    let mut dr: R1csProverDriver<pasta_curves::Fp> = R1csProverDriver::default();
    // Wire previous root
    let mut root_w = dr.alloc_witness_value(prev_state_root);
    // Apply each gram via unified update
    for (g, is_mem) in grams.iter().zip(membership_flags.iter().copied()) {
        let gram_f = g.to_field().expect("canonical Fp");
        let gram_w = dr.alloc_witness_value(gram_f);
        let sel_w = alloc_private_bit(&mut dr, is_mem);
        let out_w = dr.alloc_witness_value(pasta_curves::Fp::ZERO);
        update_unified_accum(&mut dr, root_w.clone(), gram_w, sel_w, out_w.clone(), params.domain_tag);
        root_w = out_w;
    }
    // Derive fold digest as Poseidon(tag, prev_fold, new_root)
    let new_root = match root_w { Wire::Var(v) => dr.r1cs.get_assignment(v).unwrap(), _ => panic!() };
    let new_fold = crate::accum::fold_digests(prev_fold_digest, FoldDigest(new_root), 0xF011D);
    // Bundle proof in mock form (R1CS digest + assignments); backends replace this with real SNARK
    let inst = dr.r1cs.alloc_instance();
    dr.r1cs.set_assignment(inst, new_root);
    let proof = crate::backend::prove_mock::<pasta_curves::Fp>(b"block-step", &dr.r1cs, &[inst]).unwrap();
    (PcdProof { bytes: proof.to_bytes().unwrap() }, PcdOutput { accum: crate::accum::AccumDigest(new_root), fold: new_fold })
}

/// Full chain step: verify previous recursion binder (agg_prev = H(tag, agg_prev_prev, state_prev)),
/// apply unified block updates to produce next_state, then produce new recursion bind proof for (agg_prev, next_state).
/// TODO: This is a placeholder - the actual implementation would use circuits from the circuits crate
/// but that creates a circular dependency. These functions should be implemented at a higher level.
pub struct ChainStepProof { pub block_proof: Vec<u8>, pub bind_proof: Vec<u8>, pub next_state: pasta_curves::Fp, pub bind_agg: pasta_curves::Fp }

/*
pub fn prove_chain_step<const U: usize>(
    k: u32,
    prev_bind_agg: pasta_curves::Fp,
    prev_state: pasta_curves::Fp,
    grams: [pasta_curves::Fp; U],
    is_member: [bool; U],
) -> anyhow::Result<ChainStepProof> {
    let (block_proof, next_state) = circuits::unified_block::prove_unified_block::<U>(k, prev_bind_agg, prev_state, grams, is_member)?;
    let (bind_proof, bind_agg) = circuits::recursion::prove_poseidon_bind(prev_bind_agg, next_state, k)?;
    Ok(ChainStepProof { block_proof, bind_proof, next_state, bind_agg })
}

/// Validator API: verify only with (latest state commitment, proof bundle) and public prev_bind_agg (carried along or derivable from genesis).
pub fn verify_chain_tip(
    k: u32,
    prev_bind_agg: pasta_curves::Fp,
    tip: &ChainStepProof,
) -> anyhow::Result<bool> {
    let ok_block = verify_unified_block(k, &tip.block_proof, prev_bind_agg, tip.next_state, tip.next_state)?; // instance[2] = next_state
    if !ok_block { return Ok(false); }
    let ok_bind = verify_poseidon_bind(&tip.bind_proof, tip.bind_agg, tip.next_state, k)?;
    Ok(ok_bind)
}
*/



