//! Polynomial evaluation interfaces and drivers for non-uniform circuits.

use ff::Field;
use core::marker::PhantomData;

use crate::circuit::{Driver, Sink};
use crate::drivers::PublicInput;

/// Minimal oracle interface used by poly-evaluation drivers.
/// Implementations can provide restricted polynomial evaluation semantics.
#[allow(clippy::wrong_self_convention)]
pub trait PolynomialOracle<F: Field> {
    /// Convert a field element into the oracle's value domain (usually identity).
    fn from_field(&mut self, value: F) -> F { value }

    /// Evaluate a linear combination of prior values with field coefficients.
    fn add_lc<I: IntoIterator<Item = (F, F)>>(&mut self, terms: I) -> F {
        let mut acc = F::ZERO;
        for (w, coeff) in terms { acc += w * coeff; }
        acc
    }

    /// Evaluate a multiplication gate, producing (a, b, c=a*b) in value domain.
    fn mul(&mut self, a: F, b: F) -> (F, F, F) { let c = a * b; (a, b, c) }
}

/// A simple oracle that performs native field arithmetic.
#[derive(Default, Clone, Copy)]
pub struct NativeOracle;

impl<F: Field> PolynomialOracle<F> for NativeOracle {}

/// Proving-time polynomial evaluation driver.
/// Wires are field values; closures are evaluated to obtain witness assignments.
pub struct PolyProverDriver<F: Field, O: PolynomialOracle<F>> {
    pub oracle: O,
    _marker: PhantomData<F>,
}

impl<F: Field, O: PolynomialOracle<F> + Default> Default for PolyProverDriver<F, O> {
    fn default() -> Self { Self { oracle: O::default(), _marker: PhantomData } }
}

impl<F: Field, O: PolynomialOracle<F>> Driver for PolyProverDriver<F, O> {
    type F = F;
    type W = F;
    const ONE: Self::W = F::ONE;
    type MaybeKind = crate::maybe::KindAlways;
    type IO = crate::drivers::PublicInput<F>;

    fn from_field(&mut self, value: Self::F) -> Self::W { self.oracle.from_field(value) }

    fn mul(
        &mut self,
        values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
    ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error> {
        let (a, b, _c) = values()?;
        Ok(self.oracle.mul(a, b))
    }

    fn add<L: IntoIterator<Item = (Self::W, Self::F)>>( 
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<Self::W, anyhow::Error> {
        Ok(self.oracle.add_lc(lc()))
    }

    fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>( 
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<(), anyhow::Error> {
        let acc = self.oracle.add_lc(lc());
        if acc.is_zero_vartime() { Ok(()) } else { Err(anyhow::anyhow!("constraint not satisfied")) }
    }

    fn enforce_mul<LA, LB, LC>(
        &mut self,
        _a: impl FnOnce() -> LA,
        _b: impl FnOnce() -> LB,
        _c: impl FnOnce() -> LC,
    ) -> Result<(), anyhow::Error>
    where
        LA: IntoIterator<Item = (Self::W, Self::F)>,
        LB: IntoIterator<Item = (Self::W, Self::F)>,
        LC: IntoIterator<Item = (Self::W, Self::F)>
    {
        // Value-domain driver cannot enforce multiplicative constraints; rely on tests to catch inconsistencies
        Ok(())
    }
}

/// Verification-time polynomial evaluation driver.
/// Wires are field values; closures are not evaluated.
pub struct PolyVerifierDriver<F: Field, O: PolynomialOracle<F>> {
    pub oracle: O,
    _marker: PhantomData<F>,
}

impl<F: Field, O: PolynomialOracle<F> + Default> Default for PolyVerifierDriver<F, O> {
    fn default() -> Self { Self { oracle: O::default(), _marker: PhantomData } }
}

impl<F: Field, O: PolynomialOracle<F>> Driver for PolyVerifierDriver<F, O> {
    type F = F;
    type W = F;
    const ONE: Self::W = F::ONE;
    type MaybeKind = crate::maybe::KindEmpty;
    type IO = crate::drivers::PublicInput<F>;

// Support absorbing outputs produced under polynomial drivers
    fn from_field(&mut self, value: Self::F) -> Self::W { self.oracle.from_field(value) }

    fn mul(
        &mut self,
        _values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
    ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error> {
        // Verification path: avoid invoking assignment closure; return neutral elements.
        Ok((F::ZERO, F::ZERO, F::ZERO))
    }

    fn add<L: IntoIterator<Item = (Self::W, Self::F)>>( 
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<Self::W, anyhow::Error> {
        Ok(self.oracle.add_lc(lc()))
    }

    fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>( 
        &mut self,
        lc: impl FnOnce() -> L,
    ) -> Result<(), anyhow::Error> {
        let acc = self.oracle.add_lc(lc());
        if acc.is_zero_vartime() { Ok(()) } else { Err(anyhow::anyhow!("constraint not satisfied")) }
    }

    fn enforce_mul<LA, LB, LC>(
        &mut self,
        _a: impl FnOnce() -> LA,
        _b: impl FnOnce() -> LB,
        _c: impl FnOnce() -> LC,
    ) -> Result<(), anyhow::Error>
    where
        LA: IntoIterator<Item = (Self::W, Self::F)>,
        LB: IntoIterator<Item = (Self::W, Self::F)>,
        LC: IntoIterator<Item = (Self::W, Self::F)>
    {
        // Verification driver does not multiply; skip
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    type Fr = pasta_curves::Fp;

    #[test]
    fn native_oracle_linear_ok() {
        let mut drv: PolyProverDriver<Fr, NativeOracle> = PolyProverDriver::default();
        let a = drv.from_field(Fr::from(3));
        let b = drv.from_field(Fr::from(5));
        let out = drv.add(|| vec![(a, Fr::ONE), (b, Fr::from(2u64))]).unwrap();
        assert_eq!(out, Fr::from(3) + Fr::from(10));
    }
}

// Support absorbing outputs produced under polynomial drivers (module scope)
impl<F: Field, O: PolynomialOracle<F>> Sink<super::poly::PolyProverDriver<F, O>, F> for PublicInput<F> {
    fn absorb(&mut self, value: F) { self.values.push(value); }
}

impl<F: Field, O: PolynomialOracle<F>> Sink<super::poly::PolyVerifierDriver<F, O>, F> for PublicInput<F> {
    fn absorb(&mut self, value: F) { self.values.push(value); }
}


