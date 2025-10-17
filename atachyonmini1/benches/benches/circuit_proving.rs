//! Benchmark circuit proving and verification
//! Numan Thabit 2025

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use circuits::{PcdCore, compute_transition_digest_bytes};

fn bench_pcd_prove(c: &mut Criterion) {
    let core = PcdCore::with_k(12).unwrap();
    let prev = [1u8; 32];
    let mmr = [2u8; 32];
    let nul = [3u8; 32];
    let anch = 100u64;
    let new = compute_transition_digest_bytes(&prev, &mmr, &nul, anch);
    
    c.bench_function("pcd_prove_transition", |b| {
        b.iter(|| {
            black_box(
                core.prove_transition(
                    black_box(&prev),
                    black_box(&new),
                    black_box(&mmr),
                    black_box(&nul),
                    black_box(anch),
                )
                .unwrap(),
            )
        })
    });
}

fn bench_pcd_verify(c: &mut Criterion) {
    let core = PcdCore::with_k(12).unwrap();
    let prev = [1u8; 32];
    let mmr = [2u8; 32];
    let nul = [3u8; 32];
    let anch = 100u64;
    let new = compute_transition_digest_bytes(&prev, &mmr, &nul, anch);
    let proof = core.prove_transition(&prev, &new, &mmr, &nul, anch).unwrap();
    
    c.bench_function("pcd_verify_transition", |b| {
        b.iter(|| {
            black_box(
                core.verify_transition_proof(
                    black_box(&proof),
                    black_box(&prev),
                    black_box(&new),
                    black_box(&mmr),
                    black_box(&nul),
                    black_box(anch),
                )
                .unwrap(),
            )
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10); // Reduce samples for expensive operations
    targets = bench_pcd_prove, bench_pcd_verify
}
criterion_main!(benches);

