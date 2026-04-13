use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shadow_parsers::adsb::parse_adsb;

fn bench_adsb(c: &mut Criterion) {
    let data = vec![0x8D, 0x76, 0x1B, 0x2A, 0x58, 0x99, 0x20, 0x2E, 0x23, 0x60, 0x52, 0x00, 0x00, 0x00];
    c.bench_function("adsb_parse", |b| {
        b.iter(|| parse_adsb(black_box(&data)))
    });
}

criterion_group!(benches, bench_adsb);
criterion_main!(benches);
