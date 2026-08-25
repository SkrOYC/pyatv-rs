//! Throughput baseline for the OPACK codec.
//!
//! The payload is the one shape that actually runs in a hot loop: a Companion `_systemInfo`
//! request envelope, keys in the order `pyatv-proto-companion`'s `session.rs` emits them. Every
//! Companion command and every pushed event goes through `pack`/`unpack` once, so a regression
//! here is a regression on every keypress.
//!
//! Run with `cargo bench -p pyatv-opack`; `cargo bench --no-run` is what CI builds.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pyatv_opack::{Value, pack, unpack};

/// A realistic Companion request envelope.
///
/// Mirrors `SessionInfo::to_content` wrapped in the `_i`/`_t`/`_x`/`_c` envelope from
/// `pyatv-proto-companion`'s `message.rs`. Kept as a literal here rather than as a dependency on
/// that crate, because `pyatv-opack` must not depend on a protocol crate.
fn system_info_request() -> Value {
    Value::dict([
        ("_i", Value::from("_systemInfo")),
        ("_t", Value::from(2u64)),
        ("_x", Value::from(1_234_567u64)),
        (
            "_c",
            Value::dict([
                ("_bf", Value::from(0u64)),
                ("_cf", Value::from(512u64)),
                ("_clFl", Value::from(128u64)),
                ("_i", Value::from("6fdad309d1fe")),
                (
                    "_idsID",
                    Value::from("35443E6C-9B4A-4B0D-9C0E-1B4C2F0A7E11"),
                ),
                ("_pubID", Value::from("40:cb:c0:12:34:56")),
                ("_sf", Value::from(256u64)),
                ("_sv", Value::from("170.18")),
                ("model", Value::from("AppleTV6,2")),
                ("name", Value::from("Living Room")),
            ]),
        ),
    ])
}

fn bench_opack(criterion: &mut Criterion) {
    let value = system_info_request();
    let encoded = pack(&value).expect("the fixture packs");

    let mut group = criterion.benchmark_group("opack/companion_system_info");
    group.throughput(Throughput::Bytes(
        u64::try_from(encoded.len()).expect("the fixture fits in u64"),
    ));

    group.bench_function("pack", |bencher| {
        bencher.iter(|| pack(black_box(&value)).expect("packs"));
    });

    group.bench_function("unpack", |bencher| {
        bencher.iter(|| unpack(black_box(&encoded)).expect("unpacks"));
    });

    group.finish();
}

criterion_group!(benches, bench_opack);
criterion_main!(benches);
