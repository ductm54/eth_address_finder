use address_finder::{
    address_matches, generate_private_key, private_key_to_address, private_key_to_address_bytes,
    IncrementalKeygen, MatchRule,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(|| black_box(generate_private_key()));
    });
}

fn bench_derive(c: &mut Criterion) {
    let key = generate_private_key();
    c.bench_function("derive", |b| {
        b.iter(|| black_box(private_key_to_address(black_box(&key))));
    });
}

fn bench_match_reject(c: &mut Criterion) {
    let key = generate_private_key();
    let address = private_key_to_address(&key);
    // A 10-hex-char needle the probability of hitting is 1/16^10 ~ 1e-12 — effectively always rejects.
    let prefix = Some("0123456789".to_string());
    let suffix: Option<String> = None;
    c.bench_function("match_reject", |b| {
        b.iter(|| black_box(address_matches(black_box(&address), &prefix, &suffix)));
    });
}

fn bench_match_accept(c: &mut Criterion) {
    let key = generate_private_key();
    let address = private_key_to_address(&key);
    // Use the address's own first two hex chars (after 0x) as the prefix — always matches.
    let prefix = Some(address[2..4].to_string());
    let suffix: Option<String> = None;
    c.bench_function("match_accept", |b| {
        b.iter(|| black_box(address_matches(black_box(&address), &prefix, &suffix)));
    });
}

fn bench_pipeline_single(c: &mut Criterion) {
    // A prefix that rejects virtually every key, measuring the full hot loop cost per candidate.
    let prefix = Some("0123456789".to_string());
    let suffix: Option<String> = None;
    c.bench_function("pipeline_single", |b| {
        b.iter(|| {
            let key = generate_private_key();
            let address = private_key_to_address(&key);
            black_box(address_matches(&address, &prefix, &suffix))
        });
    });
}

fn bench_derive_bytes(c: &mut Criterion) {
    let key = generate_private_key();
    c.bench_function("derive_bytes", |b| {
        b.iter(|| black_box(private_key_to_address_bytes(black_box(&key))));
    });
}

fn bench_rule_reject(c: &mut Criterion) {
    let key = generate_private_key();
    let addr = private_key_to_address_bytes(&key);
    let rule = MatchRule::new(Some("0123456789"), None).unwrap();
    c.bench_function("rule_reject", |b| {
        b.iter(|| black_box(rule.matches(black_box(&addr))));
    });
}

fn bench_pipeline_single_bytes(c: &mut Criterion) {
    let rule = MatchRule::new(Some("0123456789"), None).unwrap();
    c.bench_function("pipeline_single_bytes", |b| {
        b.iter(|| {
            let key = generate_private_key();
            let addr = private_key_to_address_bytes(&key);
            black_box(rule.matches(&addr))
        });
    });
}

fn bench_pipeline_incremental(c: &mut Criterion) {
    let rule = MatchRule::new(Some("0123456789"), None).unwrap();
    c.bench_function("pipeline_incremental", |b| {
        let mut kg = IncrementalKeygen::new();
        b.iter(|| {
            let addr = kg.address_bytes();
            let hit = rule.matches(&addr);
            kg.advance();
            black_box(hit)
        });
    });
}

fn bench_pipeline_multi(c: &mut Criterion) {
    // Fixed batch so criterion reports throughput as addresses-per-second.
    const BATCH: u64 = 4096;
    let rule = MatchRule::new(Some("0123456789"), None).unwrap();

    let mut group = c.benchmark_group("pipeline_multi");
    group.throughput(Throughput::Elements(BATCH));

    for threads in [1usize, 2, 4, 8] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        group.bench_function(format!("t={threads}"), |b| {
            b.iter(|| {
                pool.install(|| {
                    (0..BATCH).into_par_iter().for_each(|_| {
                        let key = generate_private_key();
                        let addr = private_key_to_address_bytes(&key);
                        black_box(rule.matches(&addr));
                    });
                });
            });
        });
    }
    group.finish();
}

fn bench_pipeline_multi_incremental(c: &mut Criterion) {
    const BATCH: u64 = 65_536; // larger batch — each candidate is ~10× cheaper
    let rule = MatchRule::new(Some("0123456789"), None).unwrap();

    let mut group = c.benchmark_group("pipeline_multi_incremental");
    group.throughput(Throughput::Elements(BATCH));

    for threads in [1usize, 2, 4, 8] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        group.bench_function(format!("t={threads}"), |b| {
            b.iter(|| {
                pool.install(|| {
                    // One seed scalar mult per thread, then BATCH/threads
                    // incremental steps on each thread.
                    (0..threads as u64).into_par_iter().for_each(|_| {
                        let mut kg = IncrementalKeygen::new();
                        let per_thread = BATCH / threads as u64;
                        for _ in 0..per_thread {
                            let addr = kg.address_bytes();
                            black_box(rule.matches(&addr));
                            kg.advance();
                        }
                    });
                });
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_derive,
    bench_derive_bytes,
    bench_match_reject,
    bench_match_accept,
    bench_rule_reject,
    bench_pipeline_single,
    bench_pipeline_single_bytes,
    bench_pipeline_incremental,
    bench_pipeline_multi,
    bench_pipeline_multi_incremental,
);
criterion_main!(benches);
