//! Throughput baseline for the DNS message codec.
//!
//! Every multicast datagram a scan receives is fed straight to [`DnsMessage::unpack`], including
//! the ones that turn out not to be interesting, so this runs once per packet on a busy network.
//! The fixture is the same realistic Apple TV response the unit tests in
//! `src/dns/message/tests.rs` use — a PTR plus TXT answer with SRV/A/AAAA additionals, every
//! repeated suffix compressed — duplicated here because that constant is `#[cfg(test)]` and
//! benches link against the library, not the test build.
//!
//! Run with `cargo bench -p pyatv-mdns`; `cargo bench --no-run` is what CI builds.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pyatv_mdns::DnsMessage;

/// A realistic Apple TV mDNS response, 0xab bytes, with compression pointers throughout.
///
/// Kept byte-identical to `APPLE_TV_RESPONSE` in `src/dns/message/tests.rs`; if that fixture
/// changes, change this one too so the benchmark keeps measuring the same work.
#[rustfmt::skip]
const APPLE_TV_RESPONSE: &[u8] = &[
    // header: id 0, QR|AA, 0 questions, 2 answers, 0 authorities, 3 additionals
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
    // answer 1 @0x000c: PTR _airplay._tcp.local -> "Living Room._airplay._tcp.local"
    0x08, b'_', b'a', b'i', b'r', b'p', b'l', b'a', b'y',
    0x04, b'_', b't', b'c', b'p',
    0x05, b'l', b'o', b'c', b'a', b'l',
    0x00,
    0x00, 0x0c,
    0x00, 0x01,
    0x00, 0x00, 0x11, 0x94,
    0x00, 0x0e,
    0x0b, b'L', b'i', b'v', b'i', b'n', b'g', b' ', b'R', b'o', b'o', b'm',
    0xc0, 0x0c,
    // answer 2 @0x0039: TXT, owner name compressed to 0x002b
    0xc0, 0x2b,
    0x00, 0x10,
    0x80, 0x01,
    0x00, 0x00, 0x11, 0x94,
    0x00, 0x1a,
    0x0c, b'm', b'o', b'd', b'e', b'l', b'=', b'J', b'3', b'0', b'5', b'A', b'P',
    0x0c, b'd', b'e', b'v', b'i', b'c', b'e', b'i', b'd', b'=', b'0', b'0', b'1',
    // additional 1 @0x005f: SRV, owner name compressed to 0x002b
    0xc0, 0x2b,
    0x00, 0x21,
    0x80, 0x01,
    0x00, 0x00, 0x00, 0x78,
    0x00, 0x14,
    0x00, 0x00,
    0x00, 0x00,
    0x1b, 0x58,
    0x0b, b'L', b'i', b'v', b'i', b'n', b'g', b'-', b'R', b'o', b'o', b'm',
    0xc0, 0x1a,
    // additional 2 @0x007f: A, name compressed to 0x0071
    0xc0, 0x71,
    0x00, 0x01,
    0x80, 0x01,
    0x00, 0x00, 0x00, 0x78,
    0x00, 0x04,
    192, 168, 1, 40,
    // additional 3 @0x008f: AAAA for the same host
    0xc0, 0x71,
    0x00, 0x1c,
    0x80, 0x01,
    0x00, 0x00, 0x00, 0x78,
    0x00, 0x10,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x23, 0x32, 0xff, 0xfe, 0xb1, 0x21, 0x52,
];

fn bench_dns(criterion: &mut Criterion) {
    let message = DnsMessage::unpack(APPLE_TV_RESPONSE).expect("the fixture parses");

    let mut group = criterion.benchmark_group("dns/apple_tv_response");
    group.throughput(Throughput::Bytes(
        u64::try_from(APPLE_TV_RESPONSE.len()).expect("the fixture fits in u64"),
    ));

    group.bench_function("unpack", |bencher| {
        bencher.iter(|| DnsMessage::unpack(black_box(APPLE_TV_RESPONSE)).expect("parses"));
    });

    // The compressing encoder is what a scan's outbound queries and the publisher's responses go
    // through, so it is measured alongside the decoder rather than assumed cheap.
    group.bench_function("pack_compressed", |bencher| {
        bencher.iter(|| black_box(&message).pack_compressed());
    });

    group.finish();
}

criterion_group!(benches, bench_dns);
criterion_main!(benches);
