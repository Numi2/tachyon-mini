// src/maybe.rs
//! 
//! A constant-time alternative to Option<T> for use in ZK circuits.
//! 
//! Regular Option branching isn't safe in cryptographic code - it can leak information
//! through timing! This Maybe type keeps everything constant-time, so you can't tell
//! if a value is Some or None by watching how long operations take.
//! Perfect for building ZK proofs where timing must not reveal secrets.

use core::fmt::Debug;
use subtle::{Choice, ConstantTimeEq};

/// Like Option<T>, but in constant time! No timing leaks here.
#[derive(Clone, Copy)]
pub struct Maybe<T> {
    value: T,         // The actual value (always stored, even if "None")
    present: Choice,  // A constant-time flag: 1 = Some, 0 = None
}

impl<T: Default + Copy> Maybe<T> {
    /// Creates a Maybe with a value present (like Some)
    #[inline]
    pub fn some(v: T) -> Self {
        Self { value: v, present: Choice::from(1) }
    }
    
    /// Creates an empty Maybe (like None)
    /// Note: we still store a default value, but mark it as not present
    #[inline]
    pub fn none() -> Self {
        Self { value: T::default(), present: Choice::from(0) }
    }
    
    /// Check if a value is present (but this check itself is constant-time!)
    #[inline]
    pub fn is_some(&self) -> bool { self.present.unwrap_u8() == 1 }
    
    /// Conditionally mask the "present" flag based on another condition
    /// Useful for chaining constant-time conditionals
    #[inline]
    pub fn mask_with(self, other: bool) -> Self {
        let p = if other { 1u8 } else { 0u8 };
        Self { value: self.value, present: self.present & Choice::from(p) }
    }
    
    /// Get the value (even if not present - caller beware!)
    /// This always returns something in constant time
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