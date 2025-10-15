//! Inlined DEX module facade to preserve local imports after workspace merge.
pub use dex::*;

// Re-export DEX API under wallet namespace
pub use ::dex::*;


