//! Throughput baseline for the ChaCha20-Poly1305 session transport.
//!
//! This is the hottest code in the whole stack: once a HAP session is up, every MRP protobuf and
//! every AirPlay control message is sealed and opened frame by frame, and the `HAPSession` framing
//! caps a frame at 1024 bytes — so a megabyte of MRP state updates is a thousand round trips
//! through here, each with its own AEAD setup cost.
//!
//! The nonce layout benchmarked is [`NonceLayout::PaddedCounter`] (four zero bytes followed by an
//! 8-byte little-endian counter), which is what MRP and the AirPlay HAP channels use. The AAD is
//! the 2-byte little-endian frame length, matching the `HAPSession` framing.
//!
//! Counter-advancing [`Chacha20Cipher::encrypt`]/[`Chacha20Cipher::decrypt`] are deliberately not
//! used: they take `&mut self` and would desynchronise the two directions across iterations. The
//! `*_with_nonce` variants perform the identical AEAD work under a fixed nonce.
//!
//! Run with `cargo bench -p pyatv-pairing`; `cargo bench --no-run` is what CI builds.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pyatv_pairing::chacha::{Chacha20Cipher, NONCE_LENGTH, NonceLayout};

/// The `HAPSession` frame cap (`crypto-pairing.md` §5): the largest plaintext one frame carries.
const FRAME_LENGTH: usize = 1024;

fn bench_chacha(criterion: &mut Criterion) {
    // Fixed, non-secret key material: a benchmark must be reproducible run to run, and nothing
    // here is ever put on a wire. Both directions deliberately share one key so that a frame
    // sealed on the outbound cipher opens on the inbound one — that is what lets the open
    // benchmark measure a *successful* tag verification instead of the early-out of a failing one.
    let key = [0x11u8; 32];
    let cipher = Chacha20Cipher::new(&key, &key, NonceLayout::PaddedCounter);

    let nonce: [u8; NONCE_LENGTH] = NonceLayout::PaddedCounter.nonce(0);
    let plaintext: Vec<u8> = (0..FRAME_LENGTH)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect();
    // The AAD is the two length bytes that precede the ciphertext on the wire.
    let aad = u16::try_from(FRAME_LENGTH)
        .expect("the frame cap fits in u16")
        .to_le_bytes();

    let sealed = cipher
        .encrypt_with_nonce(&plaintext, &nonce, Some(&aad))
        .expect("the fixture seals");

    let mut group = criterion.benchmark_group("chacha/hap_frame_1kib");
    group.throughput(Throughput::Bytes(
        u64::try_from(FRAME_LENGTH).expect("the frame cap fits in u64"),
    ));

    group.bench_function("seal", |bencher| {
        bencher.iter(|| {
            cipher
                .encrypt_with_nonce(black_box(&plaintext), &nonce, Some(&aad))
                .expect("seals")
        });
    });

    group.bench_function("open", |bencher| {
        bencher.iter(|| {
            cipher
                .decrypt_with_nonce(black_box(&sealed), &nonce, Some(&aad))
                .expect("opens")
        });
    });

    group.finish();
}

criterion_group!(benches, bench_chacha);
criterion_main!(benches);
