//! ragu: PCD-oriented circuit API for Tachyon
//!
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
    }

    impl<T> Maybe<T> for Empty {
        type Kind = KindEmpty;

        fn just<R>(_: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R> { Empty }

        fn with<R, E>(_: impl FnOnce() -> Result<R, E>) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E> { Ok(Empty) }

        fn take(self) -> T { unreachable!("Empty::take should be unreachable when type-checked") }

        fn map<U>(self, _: impl FnOnce(T) -> U) -> <Self::Kind as MaybeKind>::Rebind<U> { Empty }

        fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T> { Empty }
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
}

pub mod circuit {
    use ff::Field;
    use super::maybe::{MaybeKind};

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
            lc: impl FnOnce() -> L,
        ) -> Result<Self::W, anyhow::Error>;

        fn enforce_zero<L: IntoIterator<Item = (Self::W, Self::F)>>(
            &mut self,
            lc: impl FnOnce() -> L,
        ) -> Result<(), anyhow::Error>;
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
    use ff::Field;
    use crate::circuit::{Driver, Sink};

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
}


