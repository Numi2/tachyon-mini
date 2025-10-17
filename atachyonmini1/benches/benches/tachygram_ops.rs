//! Benchmark tachygram operations
//! Numan Thabit 2025

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use circuits::tachygram::{Tachygram, TachyAction};

fn bench_tachygram_add_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("tachygram_add_action");
    
    for num_actions in [1, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_actions),
            num_actions,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut tg = Tachygram::new([0u8; 32]);
                        let actions: Vec<_> = (0..size)
                            .map(|i| TachyAction {
                                payment_key: [i as u8; 32],
                                value: 100 * (i as u64 + 1),
                                nonce: [(i + 10) as u8; 32],
                                sig_r: [0u8; 32],
                                sig_s: [0u8; 32],
                            })
                            .collect();
                        (tg, actions)
                    },
                    |(mut tg, actions)| {
                        for action in actions {
                            black_box(tg.add_action(action).unwrap());
                        }
                        black_box(tg)
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
    
    group.finish();
}

fn bench_tachygram_verify_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("tachygram_verify_chain");
    
    for num_actions in [1, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_actions),
            num_actions,
            |b, &size| {
                let mut tg = Tachygram::new([0u8; 32]);
                for i in 0..size {
                    let action = TachyAction {
                        payment_key: [i as u8; 32],
                        value: 100 * (i as u64 + 1),
                        nonce: [(i + 10) as u8; 32],
                        sig_r: [0u8; 32],
                        sig_s: [0u8; 32],
                    };
                    tg.add_action(action).unwrap();
                }
                
                b.iter(|| black_box(tg.verify_chain().unwrap()))
            },
        );
    }
    
    group.finish();
}

fn bench_tachygram_chain(c: &mut Criterion) {
    let mut tg1 = Tachygram::new([0u8; 32]);
    let action1 = TachyAction {
        payment_key: [1u8; 32],
        value: 100,
        nonce: [10u8; 32],
        sig_r: [0u8; 32],
        sig_s: [0u8; 32],
    };
    tg1.add_action(action1).unwrap();
    
    c.bench_function("tachygram_chain", |b| {
        b.iter_batched(
            || {
                let mut tg2 = Tachygram::new(tg1.acc_end);
                let action2 = TachyAction {
                    payment_key: [2u8; 32],
                    value: 200,
                    nonce: [20u8; 32],
                    sig_r: [0u8; 32],
                    sig_s: [0u8; 32],
                };
                tg2.add_action(action2).unwrap();
                tg2
            },
            |tg2| black_box(tg1.clone().chain(tg2).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_tachygram_add_action,
    bench_tachygram_verify_chain,
    bench_tachygram_chain
);
criterion_main!(benches);

