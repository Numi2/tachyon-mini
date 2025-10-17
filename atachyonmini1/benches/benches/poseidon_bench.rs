//! Benchmark Poseidon hash performance
//! Numan Thabit 2025

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use circuits::compute_tachy_digest;
use pasta_curves::Fp as Fr;
use ff::Field;

fn bench_single_hash(c: &mut Criterion) {
    let pk = Fr::from(123u64);
    let value = Fr::from(1000u64);
    let nonce = Fr::from(42u64);
    
    c.bench_function("poseidon_single_digest", |b| {
        b.iter(|| {
            black_box(compute_tachy_digest(
                black_box(pk),
                black_box(value),
                black_box(nonce),
            ))
        })
    });
}

fn bench_hash_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon_batch");
    
    for batch_size in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(batch_size), batch_size, |b, &size| {
            let inputs: Vec<_> = (0..size)
                .map(|i| {
                    (
                        Fr::from(i as u64),
                        Fr::from((i * 100) as u64),
                        Fr::from((i * 7) as u64),
                    )
                })
                .collect();
            
            b.iter(|| {
                for (pk, value, nonce) in inputs.iter() {
                    black_box(compute_tachy_digest(
                        black_box(*pk),
                        black_box(*value),
                        black_box(*nonce),
                    ));
                }
            })
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_single_hash, bench_hash_batch);
criterion_main!(benches);

