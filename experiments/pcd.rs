// src/pcd.rs
// proof carrying data is like the gold that proves itself just by being. - Numan

use crate::driver::{Circuit, Driver, Instance, SynthesisError};
use crate::r1cs as cs;
use ff::PrimeField;

#[derive(Clone, Debug)]
pub struct PcdData<F: PrimeField> {
    pub old_root: F,
    pub new_root: F,
    pub metadata: F,
    pub accumulator: F,
}

#[derive(Clone, Debug)]
pub struct Pcd<F: PrimeField, Inner> {
    pub data: PcdData<F>,
    pub instance: Instance<F>,
    pub inner: Inner,
    pub depth: u64,
}

pub trait RecursionBackend<F: PrimeField> {
    type Proof: Clone + Send + Sync + 'static;

    fn allocate_prev<D: Driver<F>>(
        &self,
        d: &mut D,
        prev: Option<&Pcd<F, Self::Proof>>,
    ) -> Result<(), SynthesisError>;

    fn prove(&self, inst: &Instance<F>, tr: &FsTranscript) -> Self::Proof;

    fn verify(&self, inst: &Instance<F>, proof: &Self::Proof) -> bool;
}

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

    pub fn absorb_field<Ff: PrimeField>(&mut self, f: &Ff) {
        self.state.extend_from_slice(Ff::to_repr(f).as_ref());
    }

    pub fn absorb(&mut self, bytes: &[u8]) { self.absorb_bytes(bytes); }

    pub fn challenge_bytes(&self, label: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.state);
        h.update(label);
        *h.finalize().as_bytes()
    }
}

#[derive(Clone, Default)]
pub struct TranscriptBackend;

impl<F: PrimeField> RecursionBackend<F> for TranscriptBackend {
    type Proof = [u8; 32];

    fn allocate_prev<D: Driver<F>>(
        &self,
        _d: &mut D,
        _prev: Option<&Pcd<F, Self::Proof>>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn prove(&self, inst: &Instance<F>, tr: &FsTranscript) -> Self::Proof {
        let mut t = FsTranscript::new(b"tachyon/pcd");
        for x in &inst.inputs { t.absorb_field(x); }
        t.absorb(&tr.challenge_bytes(b"context"));
        t.challenge_bytes(b"proof")
    }

    fn verify(&self, inst: &Instance<F>, proof: &Self::Proof) -> bool {
        let recomputed = {
            let mut t = FsTranscript::new(b"tachyon/pcd");
            for x in &inst.inputs { t.absorb_field(x); }
            t.absorb(&FsTranscript::default().challenge_bytes(b"context"));
            t.challenge_bytes(b"proof")
        };
        &recomputed == proof
    }
}

pub fn prove_step<F, C, B, D>(
    backend: &B,
    circuit: &C,
    mut driver: D,
    prev: Option<&Pcd<F, B::Proof>>,
    data: PcdData<F>,
) -> Result<Pcd<F, B::Proof>, SynthesisError>
where
    F: PrimeField,
    C: Circuit<F, Input = PcdData<F>, Output = ()>,
    B: RecursionBackend<F>,
    D: Driver<F, Var = cs::Var>,
{
    backend.allocate_prev(&mut driver, prev)?;

    let inp_old = driver.input_public(data.old_root);
    let inp_new = driver.input_public(data.new_root);
    let inp_meta = driver.input_public(data.metadata);
    let inp_acc = driver.input_public(data.accumulator);

    let prod = driver.mul(inp_meta, inp_acc);
    let rhs = driver.add(inp_old, prod);
    driver.enforce_zero(cs::LinComb::from_var(inp_new).add_term(rhs, -F::ONE));

    circuit.synthesize(&mut driver, data.clone());

    let instance = driver.instance();
    let mut tr = FsTranscript::new(b"tachyon/step");
    tr.absorb(&u64::to_le_bytes(prev.map(|p| p.depth).unwrap_or(0)));
    let proof = backend.prove(&instance, &tr);

    Ok(Pcd { data, instance, inner: proof, depth: prev.map(|p| p.depth + 1).unwrap_or(1) })
}

pub fn verify_step<F, B: RecursionBackend<F>>(
    backend: &B,
    p: &Pcd<F, B::Proof>,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
{
    if backend.verify(&p.instance, &p.inner) { Ok(()) } else { Err(SynthesisError::Verification) }
}
