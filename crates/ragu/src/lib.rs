//! ragu: PCD-oriented circuit API for Tachyon mini
//! Numan Thabit 2025
//! Minimal scaffolding: Maybe, Driver, Circuit traits.

pub mod maybe {
    /// Marker for the kind of Maybe storage (Always vs Empty)
    pub trait MaybeKind {
        type Rebind<T>: Maybe<T, Kind = Self>;
    }

    /// Generalized Option-like interface where the variant is encoded in the type
    pub trait Maybe<T> {
        type Kind: MaybeKind;

        fn just<R>(f: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R>;
        fn with<R, E>(f: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E>;
        fn take(self) -> T;
        fn map<U>(self, f: impl FnOnce(T) -> U) -> <Self::Kind as MaybeKind>::Rebind<U>;
        fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T>;
        fn snag(&self) -> &T where Self: Sized { self.view().take() }
        /// Mutable view of the inner value if present; no-op for Empty
        fn view_mut(&mut self) -> <Self::Kind as MaybeKind>::Rebind<&mut T>;
        /// Monadic bind; chains operations without allocating in Empty case
        fn and_then<U>(self, f: impl FnOnce(T) -> <Self::Kind as MaybeKind>::Rebind<U>) -> <Self::Kind as MaybeKind>::Rebind<U>;
    }

    /// Always-present wrapper
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Always<T>(pub T);

    /// Zero-sized empty value
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Empty;

    pub enum KindAlways {}
    pub enum KindEmpty {}

    impl MaybeKind for KindAlways {
        type Rebind<T> = Always<T>;
    }

    impl MaybeKind for KindEmpty {
        type Rebind<T> = Empty;
    }

    impl<T> Maybe<T> for Always<T> {
        type Kind = KindAlways;

        fn just<R>(f: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R> {
            Always(f())
        }

        fn with<R, E>(f: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E> {
            Ok(Always(f()?))
        }

        fn take(self) -> T { self.0 }

        fn map<U>(self, f: impl FnOnce(T) -> U) -> <Self::Kind as MaybeKind>::Rebind<U> {
            Always(f(self.0))
        }

        fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T> { Always(&self.0) }

        fn view_mut(&mut self) -> <Self::Kind as MaybeKind>::Rebind<&mut T> { Always(&mut self.0) }

        fn and_then<U>(self, f: impl FnOnce(T) -> <Self::Kind as MaybeKind>::Rebind<U>) -> <Self::Kind as MaybeKind>::Rebind<U> {
            f(self.0)
        }
    }

    impl<T> Maybe<T> for Empty {
        type Kind = KindEmpty;

        fn just<R>(_: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R> { Empty }

        fn with<R, E>(_: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E> { Ok(Empty) }

        fn take(self) -> T { unreachable!("Empty::take should be unreachable when type-checked") }

        fn map<U>(self, _: impl FnOnce(T) -> U) -> <Self::Kind as MaybeKind>::Rebind<U> { Empty }

        fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T> { Empty }

        fn view_mut(&mut self) -> <Self::Kind as MaybeKind>::Rebind<&mut T> { Empty }

        fn and_then<U>(self, _f: impl FnOnce(T) -> <Self::Kind as MaybeKind>::Rebind<U>) -> <Self::Kind as MaybeKind>::Rebind<U> { Empty }
    }

    /// Factory to construct Maybe values for a given Kind without naming the concrete wrapper
    pub trait MaybeFactory {
        type Kind: MaybeKind;
        fn unit() -> <Self::Kind as MaybeKind>::Rebind<()>;
        fn from<T>(value: T) -> <Self::Kind as MaybeKind>::Rebind<T>;
    }

    impl MaybeFactory for KindAlways {
        type Kind = KindAlways;
        fn unit() -> <Self::Kind as MaybeKind>::Rebind<()> { Always(()) }
        fn from<T>(value: T) -> <Self::Kind as MaybeKind>::Rebind<T> { Always(value) }
    }

    impl MaybeFactory for KindEmpty {
        type Kind = KindEmpty;
        fn unit() -> <Self::Kind as MaybeKind>::Rebind<()> { Empty }
        fn from<T>(_value: T) -> <Self::Kind as MaybeKind>::Rebind<T> { Empty }
    }

    /// Extension trait implemented only for present (Always) values to safely extract contents
    pub trait Present<T>: Maybe<T> {
        fn take_present(self) -> T;
        fn snag_present(&self) -> &T;
    }

    impl<T> Present<T> for Always<T> {
        #[inline(always)]
        fn take_present(self) -> T { self.0 }
        #[inline(always)]
        fn snag_present(&self) -> &T { &self.0 }
    }
}

pub mod circuit {
    #![allow(clippy::wrong_self_convention, clippy::type_complexity)]
    use ff::Field;
    use super::maybe::{MaybeKind};
    // Bring trait methods (including associated fns) into scope for Maybe
    use super::maybe::Maybe;

    pub trait Sink<D: Driver, W> {
        fn absorb(&mut self, value: W);
    }

    pub trait Driver: Sized {
        type F: Field;
        type W: Clone;
        const ONE: Self::W;
        type MaybeKind: MaybeKind;
        type IO: Sink<Self, Self::W>;

        /// Convert a field element into a driver wire/value.
        /// Drivers that represent wires as positions may allocate a constant wire.
        fn from_field(&mut self, value: Self::F) -> Self::W;

        fn mul(
            &mut self,
            values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
        ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error>;

        fn add<L: IntoIterator<Item = (Self::W, Self::F)>>( 
            &mut self,
            _lc: impl FnOnce() -> L,
        ) -> Result<Self::W, anyhow::Error>;

        fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>( 
            &mut self,
            _lc: impl FnOnce() -> L,
        ) -> Result<(), anyhow::Error>;

        /// Enforce a multiplication relation between three linear combinations A, B and C:
        /// <A, x> * <B, x> = <C, x>
        fn enforce_mul<LA, LB, LC>(
            &mut self,
            _a: impl FnOnce() -> LA,
            _b: impl FnOnce() -> LB,
            _c: impl FnOnce() -> LC,
        ) -> Result<(), anyhow::Error>
        where
            LA: IntoIterator<Item = (Self::W, Self::F)>,
            LB: IntoIterator<Item = (Self::W, Self::F)>,
            LC: IntoIterator<Item = (Self::W, Self::F)> { Ok(()) }

        /// Convenience: obtain a representation of the field-one constant in the driver's wire domain
        #[inline(always)]
        fn one(&mut self) -> Self::W { self.from_field(Self::F::ONE) }

        /// Convenience: construct a Maybe value bound to this driver's MaybeKind
        #[inline(always)]
        fn just<T>(&mut self, f: impl FnOnce() -> T) -> Witness<Self, T> {
            <Self::MaybeKind as MaybeKind>::Rebind::<T>::just(f)
        }

        /// Convenience: construct a fallible Maybe value bound to this driver's MaybeKind
        #[inline(always)]
        fn with<T, E>(&mut self, f: impl FnOnce() -> Result<T, E>) -> Result<Witness<Self, T>, E> {
            <Self::MaybeKind as MaybeKind>::Rebind::<T>::with(f)
        }
    }

    pub type Witness<D, T> = <<D as Driver>::MaybeKind as MaybeKind>::Rebind<T>;

    pub trait Circuit<F: Field>: Sized {
        type Instance<'instance>;
        type IO<'source, D: Driver<F = F>>;
        type Witness<'witness>;
        type Aux<'witness>;

        fn input<'instance, D: Driver<F = F>>(
            &self,
            dr: &mut D,
            input: Witness<D, Self::Instance<'instance>>,
        ) -> Result<Self::IO<'instance, D>, anyhow::Error>;

        fn main<'witness, D: Driver<F = F>>(
            &self,
            dr: &mut D,
            witness: Witness<D, Self::Witness<'witness>>,
        ) -> Result<(Self::IO<'witness, D>, Witness<D, Self::Aux<'witness>>), anyhow::Error>;

        fn output<'source, D: Driver<F = F>>(
            &self,
            dr: &mut D,
            io: Self::IO<'source, D>,
            output: &mut D::IO,
        ) -> Result<(), anyhow::Error>;
    }
}

pub mod drivers {
    #![allow(clippy::wrong_self_convention)]
    use ff::Field;
    use crate::circuit::{Circuit, Driver, Sink};
    use crate::maybe::{Always};
    use core::marker::PhantomData;

    /// Sink that collects public inputs/outputs as field elements
    #[derive(Default)]
    pub struct PublicInput<F: Field> {
        pub values: Vec<F>,
    }

    impl<F: Field> Sink<PublicInputDriver<F>, F> for PublicInput<F> {
        fn absorb(&mut self, value: F) {
            self.values.push(value);
        }
    }

    /// Driver that treats wires as field values and only enforces linear constraints by checking they sum to zero
    pub struct PublicInputDriver<F: Field> {
        _marker: core::marker::PhantomData<F>,
    }

    impl<F: Field> Default for PublicInputDriver<F> {
        fn default() -> Self { Self { _marker: core::marker::PhantomData } }
    }

    impl<F: Field> Driver for PublicInputDriver<F> {
        type F = F;
        type W = F;
        const ONE: Self::W = F::ONE;
        type MaybeKind = crate::maybe::KindAlways;
        type IO = PublicInput<F>;

        fn mul(
            &mut self,
            values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
        ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error> {
            let (a, b, c) = values()?;
            Ok((a, b, c))
        }

        fn add<L: IntoIterator<Item = (Self::W, Self::F)>>(
            &mut self,
            lc: impl FnOnce() -> L,
        ) -> Result<Self::W, anyhow::Error> {
            let mut acc = F::ZERO;
            for (w, coeff) in lc() { acc += w * coeff; }
            Ok(acc)
        }

        fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>(
            &mut self,
            lc: impl FnOnce() -> L,
        ) -> Result<(), anyhow::Error> {
            let mut acc = F::ZERO;
            for (w, coeff) in lc() { acc += w * coeff; }
            if acc.is_zero_vartime() { Ok(()) } else { Err(anyhow::anyhow!("constraint not satisfied")) }
        }

        fn from_field(&mut self, value: Self::F) -> Self::W { value }
    }

    /// Driver that models wires as indices (positions) — skeleton for proving path
    pub struct ProvingDriver<F: Field> {
        pub next_index: usize,
        _marker: PhantomData<F>,
    }

    impl<F: Field> Default for ProvingDriver<F> {
        fn default() -> Self { Self { next_index: 1, _marker: PhantomData } }
    }

    impl<F: Field> Driver for ProvingDriver<F> {
        type F = F;
        type W = usize;
        const ONE: Self::W = 0; // reserved constant wire index
        type MaybeKind = crate::maybe::KindAlways;
        type IO = PublicInput<F>;

        fn mul(
            &mut self,
            values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
        ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error> {
            // In proving path, witness exists; evaluate closure then allocate wires
            let _ = values()?;
            let a = { let i = self.next_index; self.next_index += 1; i };
            let b = { let i = self.next_index; self.next_index += 1; i };
            let c = { let i = self.next_index; self.next_index += 1; i };
            Ok((a, b, c))
        }

        fn add<L: IntoIterator<Item = (Self::W, Self::F)>>( 
            &mut self,
            _lc: impl FnOnce() -> L,
        ) -> Result<Self::W, anyhow::Error> {
            // In proving path, we avoid evaluating the linear combination eagerly
            let out = self.next_index;
            self.next_index += 1;
            Ok(out)
        }

        fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>( 
            &mut self,
            _lc: impl FnOnce() -> L,
        ) -> Result<(), anyhow::Error> {
            // In proving path, constraints are recorded by the backend; no eager evaluation
            Ok(())
        }

        fn from_field(&mut self, _value: Self::F) -> Self::W {
            let idx = self.next_index;
            self.next_index += 1;
            idx
        }
    }

    // Allow collecting outputs when using ProvingDriver; since W=usize here, 
    // we cannot map wire indices to values in this lightweight driver, so we no-op.
    impl<F: Field> Sink<ProvingDriver<F>, usize> for PublicInput<F> {
        fn absorb(&mut self, _value: usize) {
            // No-op in proving driver; real backends would map wires to values.
        }
    }

    /// Driver that treats wires as field values — skeleton for verification path
    pub struct VerificationDriver<F: Field> {
        _marker: PhantomData<F>,
    }

    impl<F: Field> Default for VerificationDriver<F> {
        fn default() -> Self { Self { _marker: PhantomData } }
    }

    impl<F: Field> Driver for VerificationDriver<F> {
        type F = F;
        type W = F;
        const ONE: Self::W = F::ONE;
        type MaybeKind = crate::maybe::KindAlways;
        type IO = PublicInput<F>;

        fn mul(
            &mut self,
            values: impl FnOnce() -> Result<(Self::F, Self::F, Self::F), anyhow::Error>,
        ) -> Result<(Self::W, Self::W, Self::W), anyhow::Error> {
            // In verification (witnessless) path, avoid invoking assignment closure
            let _ = core::mem::size_of_val(&values); // keep generic param usage
            Ok((F::ZERO, F::ZERO, F::ZERO))
        }

        fn add<L: IntoIterator<Item = (Self::W, Self::F)>>( 
            &mut self,
            lc: impl FnOnce() -> L,
        ) -> Result<Self::W, anyhow::Error> {
            let mut acc = F::ZERO;
            for (w, coeff) in lc() { acc += w * coeff; }
            Ok(acc)
        }

        fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>( 
            &mut self,
            lc: impl FnOnce() -> L,
        ) -> Result<(), anyhow::Error> {
            let mut acc = F::ZERO;
            for (w, coeff) in lc() { acc += w * coeff; }
            if acc.is_zero_vartime() { Ok(()) } else { Err(anyhow::anyhow!("constraint not satisfied")) }
        }

        fn from_field(&mut self, value: Self::F) -> Self::W { value }
    }

    impl<F: Field> Sink<VerificationDriver<F>, F> for PublicInput<F> {
        fn absorb(&mut self, value: F) {
            self.values.push(value);
        }
    }

    /// Convenience: compute public inputs for a circuit using the public-input driver
    pub fn compute_public_inputs<F: Field, C: Circuit<F>>(
        circuit: &C,
        instance: C::Instance<'_>,
    ) -> Result<Vec<F>, anyhow::Error> {
        let mut dr = PublicInputDriver::<F>::default();
        let io = circuit.input(&mut dr, Always(instance))?;
        let mut sink: PublicInput<F> = PublicInput { values: Vec::new() };
        circuit.output(&mut dr, io, &mut sink)?;
        Ok(sink.values)
    }

    /// Convenience: compute public inputs for a circuit using the public-input driver
    /// (aliases preserved for backwards compatibility)
    pub type PublicInputsDriver<F> = PublicInputDriver<F>;
}

pub mod poly;
pub mod r1cs;
pub mod gadgets;
pub mod backend;
pub mod backend_halo2;
pub mod pcd;
pub mod accum;
pub mod folding;
pub mod tachygram;
pub mod accum_unified;

#[cfg(test)]
mod tests {
    use super::maybe::*;
    use super::accum::*;
    use super::folding::*;
    use super::tachygram::Tachygram;

    #[test]
    fn maybe_always_executes_closures() {
        let mut hit = 0u32;
        let m: Always<u32> = <Always<u32> as Maybe<u32>>::with(|| { hit += 1; Ok::<u32, ()>(7u32) }).unwrap();
        assert_eq!(hit, 1);
        let v = m.map(|x| x + 1).take();
        assert_eq!(v, 8);
    }

    #[test]
    fn maybe_empty_skips_closures() {
        let mut hit = 0u32;
        let m: Empty = <Empty as Maybe<u32>>::with(|| { hit += 1; Ok::<u32, ()>(7u32) }).unwrap();
        assert_eq!(hit, 0);
        let _n: Empty = m.and_then::<u32>(|_x: u32| Empty);
    }

    #[test]
    fn zst_size_checks() {
        assert_eq!(core::mem::size_of::<Empty>(), 0);
        assert_eq!(core::mem::size_of::<Always<u64>>(), core::mem::size_of::<u64>());
    }

    #[test]
    fn accum_and_fold_basics() {
        use pasta_curves::Fp as Fr;
        let mut acc = PoseidonUnifiedAccum::new(7);
        let g1 = Tachygram::from_field(Fr::from(3));
        let g2 = Tachygram::from_field(Fr::from(9));
        acc.absorb_all(&[AccumItem::Member(g1), AccumItem::NonMember(g2)]);
        let d = acc.digest();
        let folded = fold_digests(FoldDigest(d.0), FoldDigest(d.0), 123);
        assert_ne!(folded.0, Fr::ZERO);
    }
}


