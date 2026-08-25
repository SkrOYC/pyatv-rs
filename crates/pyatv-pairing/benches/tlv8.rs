//! Throughput baseline for the TLV8 codec.
//!
//! TLV8 is on the pairing path rather than the steady-state path, so absolute speed matters less
//! here than the shape of the cost: [`Tlv8::encode`] fragments any value over 255 bytes into
//! consecutive same-tag entries, and [`Tlv8::decode`] reassembles them with a linear scan over the
//! entries seen so far. Both are quadratic in the number of fragments, and a HAP pair-setup M5
//! carries a 384-byte SRP public key plus an encrypted sub-TLV, so the fragmenting path is the
//! normal one, not an edge case.
//!
//! Run with `cargo bench -p pyatv-pairing`; `cargo bench --no-run` is what CI builds.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pyatv_pairing::{Tlv8, TlvValue};

/// A pair-setup M3-shaped message: the 384-byte SRP client public key (two fragments) and the
/// 64-byte proof, alongside the sequence number.
fn pair_setup_m3() -> Tlv8 {
    let public_key: Vec<u8> = (0..384u16)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect();
    let proof: Vec<u8> = (0..64u8).collect();

    Tlv8::new()
        .with_byte(TlvValue::SeqNo, 3)
        .with(TlvValue::PublicKey, public_key)
        .with(TlvValue::Proof, proof)
}

fn bench_tlv8(criterion: &mut Criterion) {
    let message = pair_setup_m3();
    let encoded = message.encode();

    let mut group = criterion.benchmark_group("tlv8/pair_setup_m3");
    group.throughput(Throughput::Bytes(
        u64::try_from(encoded.len()).expect("the fixture fits in u64"),
    ));

    group.bench_function("encode", |bencher| {
        bencher.iter(|| black_box(&message).encode());
    });

    group.bench_function("decode", |bencher| {
        bencher.iter(|| Tlv8::decode(black_box(&encoded)).expect("decodes"));
    });

    group.finish();
}

criterion_group!(benches, bench_tlv8);
criterion_main!(benches);
