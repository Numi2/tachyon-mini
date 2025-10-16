#![forbid(unsafe_code)]
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zip324Key(pub [u8; 32]); // secret capability key

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmountZat(pub u64);

#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("invalid parameter: {0}")]
    Invalid(&'static str),
    #[error("backend error: {0}")]
    Backend(&'static str),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub trait SpendBuilder: Send + Sync {
    type NoteRef: Clone + core::fmt::Debug + Send + Sync + 'static;

    /// Deterministically derive the ZIP‑324 capability key for an index.
    fn zip324_key_for_index(&self, coin_type: u32, idx: u32) -> Result<Zip324Key, BuilderError>;

    /// Build raw tx bytes that **fund** the ephemeral note: value = amount + fee.
    fn build_fund_ephemeral(
        &self,
        key: &Zip324Key,
        value_zat: AmountZat,
        hrp: &str,
    ) -> Result<Vec<u8>, BuilderError>;

    /// Locate the funded note on chain or in a cache.
    fn find_funded_note(
        &self,
        key: &Zip324Key,
        min_value_zat: AmountZat,
    ) -> Result<Option<Self::NoteRef>, BuilderError>;

    /// Build raw tx bytes to **sweep** the ephemeral note to the wallet’s default address.
    fn build_sweep_to_wallet(
        &self,
        note: &Self::NoteRef,
        fee_zat: AmountZat,
        hrp: &str,
    ) -> Result<Vec<u8>, BuilderError>;
}

// Simple in-memory demo implementation to make the end-to-end flow runnable.

#[derive(Clone, Debug)]
pub struct MyNoteRef {
    pub key: Zip324Key,
    pub value: AmountZat,
}

#[derive(Default)]
pub struct MySpendBuilder {
    // Maps capability key bytes to a simulated funded value (in zatoshis)
    notes: std::sync::Mutex<std::collections::HashMap<[u8; 32], u64>>,
}

impl MySpendBuilder {
    pub fn new() -> Self { Self::default() }

    fn derive_key_bytes(coin_type: u32, idx: u32) -> [u8; 32] {
        // Deterministic, non-cryptographic derivation for demo/testing
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&coin_type.to_le_bytes());
        out[4..8].copy_from_slice(&idx.to_le_bytes());
        for i in 8..32 {
            out[i] = out[i - 8] ^ 0xA5 ^ (i as u8);
        }
        out
    }
}

impl core::fmt::Debug for MySpendBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MySpendBuilder").finish()
    }
}

impl SpendBuilder for MySpendBuilder {
    type NoteRef = MyNoteRef;

    fn zip324_key_for_index(&self, coin_type: u32, idx: u32) -> Result<Zip324Key, BuilderError> {
        Ok(Zip324Key(Self::derive_key_bytes(coin_type, idx)))
    }

    fn build_fund_ephemeral(
        &self,
        key: &Zip324Key,
        value_zat: AmountZat,
        _hrp: &str,
    ) -> Result<Vec<u8>, BuilderError> {
        let mut map = self.notes.lock().map_err(|_| BuilderError::Backend("lock poisoned"))?;
        map.insert(key.0, value_zat.0);
        // Produce deterministic, unique-ish bytes for testing
        let mut bytes = Vec::with_capacity(2 + 32 + 8);
        bytes.extend_from_slice(b"FE"); // mark as "fund ephemeral"
        bytes.extend_from_slice(&key.0);
        bytes.extend_from_slice(&value_zat.0.to_le_bytes());
        Ok(bytes)
    }

    fn find_funded_note(
        &self,
        key: &Zip324Key,
        min_value_zat: AmountZat,
    ) -> Result<Option<Self::NoteRef>, BuilderError> {
        let map = self.notes.lock().map_err(|_| BuilderError::Backend("lock poisoned"))?;
        if let Some(&v) = map.get(&key.0) {
            if v >= min_value_zat.0 {
                return Ok(Some(MyNoteRef { key: *key, value: AmountZat(v) }));
            }
        }
        Ok(None)
    }

    fn build_sweep_to_wallet(
        &self,
        note: &Self::NoteRef,
        fee_zat: AmountZat,
        _hrp: &str,
    ) -> Result<Vec<u8>, BuilderError> {
        let mut map = self.notes.lock().map_err(|_| BuilderError::Backend("lock poisoned"))?;
        // Simulate consuming the note
        map.remove(&note.key.0);

        let mut bytes = Vec::with_capacity(2 + 32 + 8);
        bytes.extend_from_slice(b"SW"); // mark as "sweep"
        bytes.extend_from_slice(&note.key.0);
        bytes.extend_from_slice(&fee_zat.0.to_le_bytes());
        Ok(bytes)
    }
}


