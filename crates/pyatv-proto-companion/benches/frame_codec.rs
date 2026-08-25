//! Throughput baseline for the Companion frame codec.
//!
//! `FrameCodec` is on the path of every Companion command and every pushed event: `encode` builds
//! the 4-byte header and seals the OPACK payload with the header as AAD, and `next_frame` reverses
//! it out of a streaming buffer. Both are measured with encryption on, because that is the only
//! state a live session is ever in — the plaintext variants only exist during pairing.
//!
//! The payload is a packed Companion `_systemInfo` request, so the numbers here compose with the
//! OPACK benchmark in `pyatv-opack` to give the per-message cost of the whole Companion send path.
//!
//! Run with `cargo bench -p pyatv-proto-companion`; `cargo bench --no-run` is what CI builds.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pyatv_opack::{Value, pack};
use pyatv_proto_companion::{FrameCodec, FrameType};

/// Fixed, non-secret session keys. Nothing here is ever put on a wire; the point is a run-to-run
/// reproducible measurement, and both directions share a key so an encoded frame decodes again.
const SESSION_KEY: [u8; 32] = [0x33; 32];

/// A realistic Companion request envelope, matching `pyatv-opack`'s `benches/opack.rs` fixture.
fn system_info_payload() -> Vec<u8> {
    let value = Value::dict([
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
    ]);

    pack(&value).expect("the fixture packs").to_vec()
}

fn encrypted_codec() -> FrameCodec {
    let mut codec = FrameCodec::new();
    codec.enable_encryption(SESSION_KEY, SESSION_KEY);
    codec
}

fn bench_frame_codec(criterion: &mut Criterion) {
    let payload = system_info_payload();

    let mut group = criterion.benchmark_group("companion/frame_e_opack");
    group.throughput(Throughput::Bytes(
        u64::try_from(payload.len()).expect("the fixture fits in u64"),
    ));

    // Each iteration gets a codec whose outbound counter starts at zero. Reusing one across
    // iterations would work too, but a fresh cipher keeps the measurement independent of how many
    // times criterion decided to iterate.
    group.bench_function("encode", |bencher| {
        bencher.iter_batched_ref(
            encrypted_codec,
            |codec| {
                codec
                    .encode(FrameType::EOpack, black_box(&payload))
                    .expect("encodes")
            },
            criterion::BatchSize::SmallInput,
        );
    });

    let wire = encrypted_codec()
        .encode(FrameType::EOpack, &payload)
        .expect("the fixture encodes")
        .to_vec();

    group.bench_function("decode", |bencher| {
        bencher.iter_batched_ref(
            encrypted_codec,
            |codec| {
                codec.push(black_box(&wire));
                codec.next_frame().expect("decodes").expect("a whole frame")
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_frame_codec);
criterion_main!(benches);
