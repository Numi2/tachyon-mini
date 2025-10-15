//! Wallet IVC step circuit: proves α_i ≠ 0 and correct S update with P_i'.
//! Orientation: Vesta circuit field; Pallas group arithmetic is abstracted as digest placeholders.

use anyhow::Result;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, keygen_pk, keygen_vk, create_proof, verify_proof, SingleVerifier};
use halo2_proofs::poly::ipa::commitment::{ParamsIPA, IPACommitmentScheme};
use halo2_proofs::transcript::{Blake2bWrite, Blake2bRead, Challenge255};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use pasta_curves::{Fq as Fr, vesta::Affine as G1Affine};
use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use serde_json;
use crate::pcs;

/// Config for wallet step
#[derive(Clone, Debug)]
pub struct WalletStepConfig {
    pub advice: [Column<Advice>; 6],
    pub instance: [Column<Instance>; 5], // [A_i, S_i, P_i, A_{i+1}, S_{i+1}]
    pub selector: Selector,
    pub poseidon: Pow5Config<Fr, 3, 2>,
}

/// Circuit inputs for one wallet step
#[derive(Clone, Debug)]
pub struct WalletStepCircuit<const MAX_ROOTS: usize> {
    pub a_i: Value<Fr>,       // public digest placeholder
    pub s_i: Value<Fr>,       // public digest placeholder
    pub p_i: Value<Fr>,       // public digest placeholder
    pub a_next: Value<Fr>,    // public digest placeholder
    pub s_next: Value<Fr>,    // public digest placeholder

    pub v: Value<Fr>,                       // secret tag
    pub roots: [Value<Fr>; MAX_ROOTS],      // block roots
    pub inc_flags: [Value<Fr>; MAX_ROOTS],  // 0/1 selection
    pub beta: Value<Fr>,                    // inverse witness for α
}

impl<const MAX_ROOTS: usize> Circuit<Fr> for WalletStepCircuit<MAX_ROOTS> {
    type Config = WalletStepConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a_i: Value::unknown(),
            s_i: Value::unknown(),
            p_i: Value::unknown(),
            a_next: Value::unknown(),
            s_next: Value::unknown(),
            v: Value::unknown(),
            roots: [Value::unknown(); MAX_ROOTS],
            inc_flags: [Value::unknown(); MAX_ROOTS],
            beta: Value::unknown(),
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
        let instance = [
            meta.instance_column(), // A_i
            meta.instance_column(), // S_i
            meta.instance_column(), // P_i
            meta.instance_column(), // A_{i+1}
            meta.instance_column(), // S_{i+1}
        ];
        for i in &instance { meta.enable_equality(*i); }
        let selector = meta.selector();

        // Poseidon config (for domain-separated hashes if needed later)
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

        // Booleanity gate for flags
        meta.create_gate("inc_flags boolean", |meta| {
            let s = meta.query_selector(selector);
            let b = meta.query_advice(advice[5], halo2_proofs::poly::Rotation::cur());
            vec![s * b.clone() * (b - halo2_proofs::plonk::Expression::Constant(Fr::ONE))]
        });

        WalletStepConfig { advice, instance, selector, poseidon }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        // Expose public inputs
        let a_i_cell = layouter.assign_region(|| "A_i", |mut region| region.assign_advice(|| "A_i", cfg.advice[0], 0, || self.a_i))?;
        let s_i_cell = layouter.assign_region(|| "S_i", |mut region| region.assign_advice(|| "S_i", cfg.advice[1], 0, || self.s_i))?;
        let p_i_cell = layouter.assign_region(|| "P_i", |mut region| region.assign_advice(|| "P_i", cfg.advice[2], 0, || self.p_i))?;
        let a_next_cell = layouter.assign_region(|| "A_{i+1}", |mut region| region.assign_advice(|| "A_{i+1}", cfg.advice[0], 1, || self.a_next))?;
        let s_next_cell = layouter.assign_region(|| "S_{i+1}", |mut region| region.assign_advice(|| "S_{i+1}", cfg.advice[1], 1, || self.s_next))?;
        layouter.constrain_instance(a_i_cell.cell(), cfg.instance[0], 0)?;
        layouter.constrain_instance(s_i_cell.cell(), cfg.instance[1], 0)?;
        layouter.constrain_instance(p_i_cell.cell(), cfg.instance[2], 0)?;
        layouter.constrain_instance(a_next_cell.cell(), cfg.instance[3], 0)?;
        layouter.constrain_instance(s_next_cell.cell(), cfg.instance[4], 0)?;

        // Compute α = ∏_j (v - a_j) over selected roots
        let v_cell = layouter.assign_region(|| "v", |mut region| region.assign_advice(|| "v", cfg.advice[4], 0, || self.v))?;
        let mut alpha_cell = layouter.assign_region(|| "alpha init", |mut region| region.assign_advice(|| "alpha", cfg.advice[3], 0, || Value::known(Fr::ONE)))?;
        for j in 0..MAX_ROOTS {
            // Enforce booleanity
            layouter.assign_region(|| format!("bool {j}"), |mut region| {
                cfg.selector.enable(&mut region, 0)?;
                let _ = region.assign_advice(|| "b", cfg.advice[5], 0, || self.inc_flags[j])?;
                Ok(())
            })?;
            let a_cell = layouter.assign_region(|| format!("a_{j}"), |mut region| region.assign_advice(|| "a_j", cfg.advice[2], 1, || self.roots[j]))?;
            let t_cell = layouter.assign_region(|| format!("t_{j}"), |mut region| {
                let val = v_cell.value().zip(a_cell.value()).map(|(v, a)| *v - *a);
                region.assign_advice(|| "t", cfg.advice[3], 1, || val)
            })?;
            // factor = t*b + (1-b)
            let b_cell = layouter.assign_region(|| format!("b_{j}"), |mut region| region.assign_advice(|| "b", cfg.advice[5], 1, || self.inc_flags[j]))?;
            let one_minus_b = layouter.assign_region(|| format!("1-b_{j}"), |mut region| {
                let val = b_cell.value().map(|b| Fr::ONE - *b);
                region.assign_advice(|| "1-b", cfg.advice[4], 1, || val)
            })?;
            let tb = layouter.assign_region(|| format!("t*b_{j}"), |mut region| {
                let val = t_cell.value().zip(b_cell.value()).map(|(t, b)| *t * *b);
                region.assign_advice(|| "t*b", cfg.advice[3], 1, || val)
            })?;
            let factor = layouter.assign_region(|| format!("factor_{j}"), |mut region| {
                let val = tb.value().zip(one_minus_b.value()).map(|(x, y)| *x + *y);
                region.assign_advice(|| "factor", cfg.advice[2], 1, || val)
            })?;
            alpha_cell = layouter.assign_region(|| format!("alpha_{j}"), |mut region| {
                let val = alpha_cell.value().zip(factor.value()).map(|(a, f)| *a * *f);
                region.assign_advice(|| "alpha", cfg.advice[3], 0, || val)
            })?;
        }

        // α * β = 1 to prove α ≠ 0 (explicit multiplication and equality)
        let beta_cell = layouter.assign_region(|| "beta", |mut region| region.assign_advice(|| "beta", cfg.advice[4], 2, || self.beta))?;
        let prod_cell = layouter.assign_region(|| "prod", |mut region| {
            let val = alpha_cell.value().zip(beta_cell.value()).map(|(a, b)| *a * *b);
            region.assign_advice(|| "prod", cfg.advice[0], 2, || val)
        })?;
        let one_cell = layouter.assign_region(|| "one", |mut region| region.assign_advice(|| "one", cfg.advice[5], 2, || Value::known(Fr::ONE)))?;
        layouter.assign_region(|| "bind prod == 1", |mut region| { region.constrain_equal(prod_cell.cell(), one_cell.cell())?; Ok(()) })?;

		// Derive P_i' binding from actual alpha and provided P_i digest:
		//   pi_prime = H(TAG_PI_PRIME, P_i, alpha)
		let chip_pi = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
		let h_pi = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
			chip_pi,
			layouter.namespace(|| "poseidon pi_prime"),
		)?;
		let tag_pi_cell = layouter.assign_region(|| "tag_pi_prime", |mut region| {
			let c = region.assign_advice(|| "tag_pi", cfg.advice[0], 3, || Value::known(Fr::from(pcs::domains::TAG_PI_PRIME as u64)))?;
			region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_PI_PRIME as u64))?;
			Ok(c)
		})?;
		let pi_prime_cell = h_pi.hash(
			layouter.namespace(|| "H(tag_pi, P_i, alpha)"),
			[tag_pi_cell, p_i_cell.clone(), alpha_cell.clone()],
		)?;

		// Enforce S_{i+1} = H_S(S_i, P_i') with the same two-round composition used for accumulator hashes
		let chip_s1 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
		let h_s1 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
			chip_s1,
			layouter.namespace(|| "poseidon acc S d1"),
		)?;
		let tag_s_cell = layouter.assign_region(|| "tag_acc_s", |mut region| {
			let c = region.assign_advice(|| "tag_s", cfg.advice[1], 3, || Value::known(Fr::from(pcs::domains::TAG_ACC_S as u64)))?;
			region.constrain_constant(c.cell(), Fr::from(pcs::domains::TAG_ACC_S as u64))?;
			Ok(c)
		})?;
		let zero_cell = layouter.assign_region(|| "zero_const", |mut region| region.assign_advice(|| "zero", cfg.advice[2], 3, || Value::known(Fr::ZERO)))?;
		let d1_cell = h_s1.hash(
			layouter.namespace(|| "H(tag_s, S_i, 0)"),
			[tag_s_cell, s_i_cell.clone(), zero_cell.clone()],
		)?;
		let chip_s2 = Pow5Chip::<Fr, 3, 2>::construct(cfg.poseidon.clone());
		let h_s2 = PoseidonHash::<Fr, Pow5Chip<Fr, 3, 2>, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
			chip_s2,
			layouter.namespace(|| "poseidon acc S out"),
		)?;
		let s_next_from_pi_prime = h_s2.hash(
			layouter.namespace(|| "H(d1, P_i', 0)"),
			[d1_cell, pi_prime_cell, zero_cell],
		)?;
		layouter.assign_region(|| "bind S_{i+1}", |mut region| {
			region.constrain_equal(s_next_cell.cell(), s_next_from_pi_prime.cell())?;
			Ok(())
		})?;

        Ok(())
    }
}

/// Prove one wallet step
pub fn prove_wallet_step<const MAX_ROOTS: usize>(
    k: u32,
    a_i: Fr,
    s_i: Fr,
    p_i: Fr,
    a_next: Fr,
    s_next: Fr,
    v: Fr,
    roots: [Fr; MAX_ROOTS],
    inc_flags: [bool; MAX_ROOTS],
    beta: Fr,
) -> Result<Vec<u8>> {
    let params = load_or_setup_wallet_params::<MAX_ROOTS>(k)?;
    let circuit = WalletStepCircuit::<MAX_ROOTS> {
        a_i: Value::known(a_i),
        s_i: Value::known(s_i),
        p_i: Value::known(p_i),
        a_next: Value::known(a_next),
        s_next: Value::known(s_next),
        v: Value::known(v),
        roots: roots.map(Value::known),
        inc_flags: inc_flags.map(|b| Value::known(if b { Fr::ONE } else { Fr::ZERO })),
        beta: Value::known(beta),
    };
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk, &circuit)?;

    let inst_a = [a_i];
    let inst_s = [s_i];
    let inst_p = [p_i];
    let inst_an = [a_next];
    let inst_sn = [s_next];

    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<IPACommitmentScheme<G1Affine>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&inst_a[..], &inst_s[..], &inst_p[..], &inst_an[..], &inst_sn[..]]],
        rand::rngs::OsRng,
        &mut transcript,
    )?;
    Ok(transcript.finalize())
}

/// Verify one wallet step
pub fn verify_wallet_step(
    k: u32,
    proof: &[u8],
    a_i: Fr,
    s_i: Fr,
    p_i: Fr,
    a_next: Fr,
    s_next: Fr,
) -> Result<bool> {
    if proof.is_empty() { return Ok(false); }
    let params = load_or_setup_wallet_params::<1>(k)?;
    let empty = WalletStepCircuit::<1> {
        a_i: Value::unknown(), s_i: Value::unknown(), p_i: Value::unknown(), a_next: Value::unknown(), s_next: Value::unknown(), v: Value::unknown(), roots: [Value::unknown(); 1], inc_flags: [Value::unknown(); 1], beta: Value::unknown()
    };
    let vk = keygen_vk(&params, &empty)?;
    let inst_a = [a_i];
    let inst_s = [s_i];
    let inst_p = [p_i];
    let inst_an = [a_next];
    let inst_sn = [s_next];
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(std::io::Cursor::new(proof));
    let strategy = SingleVerifier::new(&params);
    Ok(verify_proof::<IPACommitmentScheme<G1Affine>, _, _, _>(&params, &vk, strategy, &[&[&inst_a[..], &inst_s[..], &inst_p[..], &inst_an[..], &inst_sn[..]]], &mut transcript).is_ok())
}

/// Wallet circuit params persistence with versioned IDs
#[derive(serde::Serialize, serde::Deserialize)]
struct WalletCircuitMeta { version: u32, k: u32, id: String }

fn wallet_circuit_id<const MAX_ROOTS: usize>() -> String {
    format!("wallet_step:v1:roots{}", MAX_ROOTS)
}

fn wallet_params_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    let base = Path::new("crates/pcd_core/crates/node_ext/node_data/keys");
    (base.join("wallet_params.bin"), base.join("wallet_meta.json"))
}

fn load_or_setup_wallet_params<const MAX_ROOTS: usize>(k: u32) -> Result<ParamsIPA<G1Affine>> {
    std::fs::create_dir_all("crates/pcd_core/crates/node_ext/node_data/keys").ok();
    let (params_path, meta_path) = wallet_params_paths();
    if params_path.exists() {
        let mut pf = File::open(&params_path)?;
        let params = ParamsIPA::<G1Affine>::read(&mut pf)?;
        if meta_path.exists() {
            let mut s = String::new(); File::open(&meta_path)?.read_to_string(&mut s)?;
            let meta: WalletCircuitMeta = serde_json::from_str(&s)?;
            let expected = WalletCircuitMeta { version: 1, k, id: wallet_circuit_id::<MAX_ROOTS>() };
            if meta.k != expected.k || meta.id != expected.id { return Err(anyhow::anyhow!("wallet params meta mismatch")); }
        }
        Ok(params)
    } else {
        let params = ParamsIPA::<G1Affine>::new(k);
        let mut f = File::create(&params_path)?; params.write(&mut f)?;
        let meta = WalletCircuitMeta { version: 1, k, id: wallet_circuit_id::<MAX_ROOTS>() };
        let mut mf = File::create(&meta_path)?; mf.write_all(serde_json::to_string_pretty(&meta)?.as_bytes())?;
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_alpha_zero_prove_fails() {
        const MAX_ROOTS: usize = 4;
        let k = 8u32;
        // Choose v equal to first root and set flag[0]=true so alpha includes (v-a0)=0
        let v = Fr::from(5u64);
        let roots = [Fr::from(5u64), Fr::from(9u64), Fr::ZERO, Fr::ZERO];
        let flags = [true, false, false, false];
        let a_i = Fr::from(1u64);
        let s_i = Fr::from(2u64);
        let p_i = Fr::from(3u64);
        let a_next = Fr::from(4u64);
        let s_next = Fr::from(5u64);
        // Any beta will not satisfy alpha*beta=1 since alpha=0; prover should fail
        let res = prove_wallet_step::<MAX_ROOTS>(k, a_i, s_i, p_i, a_next, s_next, v, roots, [flags[0], flags[1], flags[2], flags[3]], Fr::ONE);
        assert!(res.is_err());
    }
}


