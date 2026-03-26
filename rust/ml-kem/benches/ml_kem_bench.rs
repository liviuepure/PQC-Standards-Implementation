use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ml_kem::kem::{keygen, encapsulate, decapsulate};
use ml_kem::params::{MlKem512, MlKem768, MlKem1024, ParameterSet};
use rand::rngs::OsRng;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-kem-keygen");
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| keygen::<MlKem512>(black_box(&mut OsRng)))
    });
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| keygen::<MlKem768>(black_box(&mut OsRng)))
    });
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| keygen::<MlKem1024>(black_box(&mut OsRng)))
    });
    group.finish();
}

fn bench_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-kem-encaps");

    let (ek512, _) = keygen::<MlKem512>(&mut OsRng);
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| encapsulate::<MlKem512>(black_box(&ek512), black_box(&mut OsRng)))
    });

    let (ek768, _) = keygen::<MlKem768>(&mut OsRng);
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| encapsulate::<MlKem768>(black_box(&ek768), black_box(&mut OsRng)))
    });

    let (ek1024, _) = keygen::<MlKem1024>(&mut OsRng);
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| encapsulate::<MlKem1024>(black_box(&ek1024), black_box(&mut OsRng)))
    });

    group.finish();
}

fn bench_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-kem-decaps");

    let (ek512, dk512) = keygen::<MlKem512>(&mut OsRng);
    let (_, ct512) = encapsulate::<MlKem512>(&ek512, &mut OsRng);
    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| decapsulate::<MlKem512>(black_box(&dk512), black_box(&ct512)))
    });

    let (ek768, dk768) = keygen::<MlKem768>(&mut OsRng);
    let (_, ct768) = encapsulate::<MlKem768>(&ek768, &mut OsRng);
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| decapsulate::<MlKem768>(black_box(&dk768), black_box(&ct768)))
    });

    let (ek1024, dk1024) = keygen::<MlKem1024>(&mut OsRng);
    let (_, ct1024) = encapsulate::<MlKem1024>(&ek1024, &mut OsRng);
    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| decapsulate::<MlKem1024>(black_box(&dk1024), black_box(&ct1024)))
    });

    group.finish();
}

fn bench_full_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-kem-roundtrip");
    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
            let (ss, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);
            let ss2 = decapsulate::<MlKem768>(&dk, &ct);
            black_box((ss, ss2));
        })
    });
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encaps, bench_decaps, bench_full_roundtrip);
criterion_main!(benches);
