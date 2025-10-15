//playing around with fiat shamir over blake3 , poseidon2 is the natural choice -  Numan
//! Fiat–Shamir transcript over BLAKE3.

use blake3::Hasher;
use ff::PrimeField;

#[derive(Default, Clone)]
pub struct FsTranscript {
    state: Vec<u8>,
}

impl FsTranscript {
    pub fn new(label: &[u8]) -> Self {
        let mut t = Self { state: Vec::new() };
        t.absorb(label);
        t
    }

    pub fn absorb_bytes(&mut self, bytes: &[u8]) { self.state.extend_from_slice(bytes); }

    pub fn absorb_field<F: PrimeField>(&mut self, f: &F) { self.state.extend_from_slice(f.to_repr().as_ref()); }

    pub fn absorb(&mut self, bytes: &[u8]) { self.absorb_bytes(bytes); }

    pub fn challenge_bytes(&self, label: &[u8]) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(&self.state);
        h.update(label);
        *h.finalize().as_bytes()
    }
}