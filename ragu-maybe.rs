// src/maybe.rs
//! Branch-friendly substitute for Option<T> during synthesis.

use core::fmt::Debug;
use subtle::{Choice, ConstantTimeEq};

#[derive(Clone, Copy)]
pub struct Maybe<T> {
    value: T,
    present: Choice,
}

impl<T: Default + Copy> Maybe<T> {
    #[inline]
    pub fn some(v: T) -> Self {
        Self { value: v, present: Choice::from(1) }
    }
    #[inline]
    pub fn none() -> Self {
        Self { value: T::default(), present: Choice::from(0) }
    }
    #[inline]
    pub fn is_some(&self) -> bool { self.present.unwrap_u8() == 1 }
    #[inline]
    pub fn mask_with(self, other: bool) -> Self {
        let p = if other { 1u8 } else { 0u8 };
        Self { value: self.value, present: self.present & Choice::from(p) }
    }
    #[inline]
    pub fn value_or_default(self) -> T { self.value }
}

impl<T: Debug> Debug for Maybe<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_some() { write!(f, "Maybe::some({:?})", self.value) } else { write!(f, "Maybe::none") }
    }
}

impl<T: ConstantTimeEq> ConstantTimeEq for Maybe<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.present.ct_eq(&other.present) & self.value.ct_eq(&other.value)
    }
}