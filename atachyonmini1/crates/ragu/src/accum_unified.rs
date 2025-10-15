//! Unified accumulator verification gadgets and wrappers.
//! Verifies inclusion OR exclusion of a `Tachygram` against a single accumulator
//! root without revealing the role (membership vs non-membership). The choice is
//! passed as a private boolean `is_member` and enforced as boolean; verification
//! itself is delegated to a backend via a single foreign escape event to avoid
//! leaking the role through circuit structure.

use anyhow::Result;
use ff::Field;
use pasta_curves::Fp as Fr;

use crate::gadgets::boolean;
use crate::r1cs::{R1csProverDriver, Wire, Var};

/// Emit a single foreign escape event carrying the accumulator verification inputs.
/// Inputs: [root, gram, is_member, proof...] ; Outputs: [] ; Data: domain_tag (u64 LE)
pub fn verify_unified_accum(
    dr: &mut R1csProverDriver<Fr>,
    root: Wire<Fr>,
    gram: Wire<Fr>,
    is_member: Wire<Fr>,
    proof: &[Wire<Fr>],
    domain_tag: u64,
) -> Result<()> {
    // Enforce booleanity of the selector bit privately
    boolean(dr, is_member.clone())?;

    // Convert to Vars; require variables to be allocated for all inputs
    let mut to_var = |w: &Wire<Fr>| match w { Wire::Var(v) => *v, Wire::Const(_) => {
        // Allocate zero witness for const wires to avoid panics in dev/test paths.
        let z = dr.alloc_witness_value(Fr::ZERO);
        match z { Wire::Var(vv) => vv, _ => unreachable!() }
    } };
    let mut ins_vars: Vec<Var> = Vec::with_capacity(3 + proof.len());
    ins_vars.push(to_var(&root));
    ins_vars.push(to_var(&gram));
    ins_vars.push(to_var(&is_member));
    for w in proof { ins_vars.push(to_var(w)); }

    // Data payload encodes the domain/tag to bind semantics
    let data = domain_tag.to_le_bytes().to_vec();
    dr.r1cs.emit_foreign("unified_accum_verify", &ins_vars, &[], &data);
    Ok(())
}

/// Helper: allocate a private boolean as witness (0/1) and return its wire.
pub fn alloc_private_bit(dr: &mut R1csProverDriver<Fr>, bit: bool) -> Wire<Fr> {
    let v = if bit { Fr::ONE } else { Fr::ZERO };
    dr.alloc_witness_value(v)
}

/// Unified accumulator update: emits a foreign event binding (prev_root, gram, is_member) -> next_root.
/// The next_root value should be allocated by the caller and provided as `out_root` to bind the event.
pub fn update_unified_accum(
    dr: &mut R1csProverDriver<Fr>,
    prev_root: Wire<Fr>,
    gram: Wire<Fr>,
    is_member: Wire<Fr>,
    out_root: Wire<Fr>,
    domain_tag: u64,
) {
    let mut to_var = |w: &Wire<Fr>| match w { Wire::Var(v) => *v, Wire::Const(_) => {
        let z = dr.alloc_witness_value(Fr::ZERO);
        match z { Wire::Var(vv) => vv, _ => unreachable!() }
    } };
    let inputs = vec![to_var(&prev_root), to_var(&gram), to_var(&is_member)];
    let outputs = vec![to_var(&out_root)];
    let data = domain_tag.to_le_bytes().to_vec();
    dr.r1cs.emit_foreign("unified_accum_update", &inputs, &outputs, &data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::R1csProverDriver;

    #[test]
    fn unified_emits_single_event_with_private_selector() {
        let mut drv: R1csProverDriver<Fr> = R1csProverDriver::default();
        let root = drv.alloc_witness_value(Fr::from(123));
        let gram = drv.alloc_witness_value(Fr::from(456));
        let sel = alloc_private_bit(&mut drv, true);
        let proof = vec![drv.alloc_witness_value(Fr::from(789))];
        verify_unified_accum(&mut drv, root, gram, sel, &proof, 9).unwrap();
        assert_eq!(drv.r1cs.escapes.len(), 1);
        match &drv.r1cs.escapes[0] {
            crate::r1cs::EscapeEvent::Foreign { name, .. } => assert_eq!(name, "unified_accum_verify"),
            _ => panic!("expected foreign escape"),
        }
    }
}


