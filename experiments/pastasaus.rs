// src/pasta.rs 
//! Pasta cycle aliases and helpers.

use pasta_curves::{pallas, vesta};
use ff::PrimeField;

/// Scalar field of Vesta = base field of Pallas.
pub type FrVesta = vesta::Scalar;

/// Scalar field of Pallas = base field of Vesta.
pub type FrPallas = pallas::Scalar;

/// Wide-reduction helper for Pasta scalars.
pub trait FromBytesWide: PrimeField {
    fn from_bytes_wide_src(w: &[u8; 64]) -> Self;
}

impl FromBytesWide for FrVesta {
    #[inline]
    fn from_bytes_wide_src(w: &[u8; 64]) -> Self { FrVesta::from_bytes_wide(w) }
}

impl FromBytesWide for FrPallas {
    #[inline]
    fn from_bytes_wide_src(w: &[u8; 64]) -> Self { FrPallas::from_bytes_wide(w) }
}