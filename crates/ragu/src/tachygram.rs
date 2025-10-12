//! Tachygrams: unified 32-byte representation for commitments and nullifiers.
//! Consensus treats them identically; circuits derive them via Poseidon-friendly
//! PRFs and commitments.

use ff::{Field, PrimeField};
use pasta_curves::Fp as Fr;

/// Fixed-length gram used for commitments and nullifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tachygram(pub [u8; 32]);

impl Tachygram {
    /// Interpret a Pasta Fp canonical representation as a Tachygram.
    pub fn from_field(f: Fr) -> Self { Self(f.to_repr().as_ref().try_into().unwrap()) }

    /// Parse a canonical Pasta Fp from the Tachygram (None if not canonical).
    pub fn to_field(&self) -> Option<Fr> {
        let mut repr = <Fr as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&self.0);
        let ct = Fr::from_repr(repr);
        let opt: Option<Fr> = ct.into();
        opt
    }

    /// Poseidon-based PRF for nullifier derivation: PRF(sk, flavor) -> Tachygram.
    /// Use domain-separated Poseidon2 t=3 with (flavor, sk, zero).
    pub fn prf_nullifier(sk: Fr, flavor: u64) -> Self {
        let tag = flavor ^ 0x6E756C6C6966; // 'nullif' cribbed tag
        let h = crate::gadgets::poseidon2_t3_hash_tagged(sk, Fr::ZERO, tag);
        Tachygram::from_field(h)
    }

    /// Poseidon-based note commitment derivation to Tachygram.
    /// For now, commit(value, rho) = H(tag, value, rho) with domain tag.
    pub fn commit_poseidon(value: Fr, rho: Fr, tag: u64) -> Self {
        let h = crate::gadgets::poseidon2_t3_hash_tagged(value, rho, tag);
        Tachygram::from_field(h)
    }
}


