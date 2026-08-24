//! Message-level tests. pyatv has no direct `DnsMessage` unit tests — it exercises the type through
//! `tests/core/test_mdns.py` against a fake responder — so these pin the framing that
//! `create_service_queries` and `MulticastDnsSdClientProtocol.datagram_received` depend on, plus
//! the round-trip behaviour compression makes possible.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{DEFAULT_FLAGS, DEFAULT_QUERY_ID, DnsHeader, DnsMessage};
use crate::dns::{
    CLASS_IN, DnsError, DnsQuestion, DnsResource, QCLASS_IN_UNICAST, QueryType, Reader, RecordData,
    SrvData, TxtRecords,
};

/// A realistic Apple TV mDNS response: a PTR announcing the instance, the SRV and TXT for it, and
/// A/AAAA records for the target host — with every repeated suffix compressed, exactly as a real
/// responder emits it.
///
/// Layout, with the offsets the compression pointers refer to:
///
/// ```text
/// 0x000c  "_airplay"        the start of _airplay._tcp.local, the PTR owner name
/// 0x001a  "local"           pointed at by the SRV target
/// 0x002b  "Living Room"     the PTR target, whose remaining labels point at 0x000c
/// 0x0071  "Living-Room"     the SRV target, pointed at by the A and AAAA records
/// ```
// The line breaks and the trailing comments are the documentation: reflowing this into dense rows
// of hex would make the offsets the pointers depend on impossible to check by eye.
#[rustfmt::skip]
const APPLE_TV_RESPONSE: &[u8] = &[
    // --- header: id 0, QR|AA, 0 questions, 2 answers, 0 authorities, 3 additionals
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
    // --- answer 1 @0x000c: PTR _airplay._tcp.local -> "Living Room._airplay._tcp.local"
    0x08, b'_', b'a', b'i', b'r', b'p', b'l', b'a', b'y', // @0x000c "_airplay"
    0x04, b'_', b't', b'c', b'p', // @0x0015 "_tcp"
    0x05, b'l', b'o', b'c', b'a', b'l', // @0x001a "local"
    0x00, // root
    0x00, 0x0c, // type PTR
    0x00, 0x01, // class IN
    0x00, 0x00, 0x11, 0x94, // ttl 4500
    0x00, 0x0e, // rdlength 14
    0x0b, b'L', b'i', b'v', b'i', b'n', b'g', b' ', b'R', b'o', b'o', b'm', // @0x002b
    0xc0, 0x0c, // -> _airplay._tcp.local
    // --- answer 2 @0x0039: TXT for the instance, owner name compressed to 0x002b
    0xc0, 0x2b, // "Living Room._airplay._tcp.local"
    0x00, 0x10, // type TXT
    0x80, 0x01, // class IN, cache-flush
    0x00, 0x00, 0x11, 0x94, // ttl 4500
    0x00, 0x1a, // rdlength 26
    0x0c, b'm', b'o', b'd', b'e', b'l', b'=', b'J', b'3', b'0', b'5', b'A', b'P',
    0x0c, b'd', b'e', b'v', b'i', b'c', b'e', b'i', b'd', b'=', b'0', b'0', b'1',
    // --- additional 1 @0x005f: SRV for the instance, owner name compressed to 0x002b
    0xc0, 0x2b, // "Living Room._airplay._tcp.local"
    0x00, 0x21, // type SRV
    0x80, 0x01, // class IN, cache-flush
    0x00, 0x00, 0x00, 0x78, // ttl 120
    0x00, 0x14, // rdlength 20
    0x00, 0x00, // priority
    0x00, 0x00, // weight
    0x1b, 0x58, // port 7000
    0x0b, b'L', b'i', b'v', b'i', b'n', b'g', b'-', b'R', b'o', b'o', b'm', // @0x0071
    0xc0, 0x1a, // -> "local"
    // --- additional 2 @0x007f: A for the target host, name compressed to 0x0071
    0xc0, 0x71, // "Living-Room.local"
    0x00, 0x01, // type A
    0x80, 0x01, // class IN, cache-flush
    0x00, 0x00, 0x00, 0x78, // ttl 120
    0x00, 0x04, // rdlength 4
    192, 168, 1, 40, //
    // --- additional 3 @0x008f: AAAA for the same host
    0xc0, 0x71, // "Living-Room.local"
    0x00, 0x1c, // type AAAA
    0x80, 0x01, // class IN, cache-flush
    0x00, 0x00, 0x00, 0x78, // ttl 120
    0x00, 0x10, // rdlength 16
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x02, 0x23, 0x32, 0xff, 0xfe, 0xb1, 0x21, 0x52,
];

#[test]
fn the_fixture_offsets_are_what_the_pointers_claim() {
    // If this fails the fixture has drifted and every pointer in it is aimed at the wrong byte.
    assert_eq!(APPLE_TV_RESPONSE.len(), 0xab);
    assert_eq!(&APPLE_TV_RESPONSE[0x0c..0x15], b"\x08_airplay");
    assert_eq!(&APPLE_TV_RESPONSE[0x1a..0x20], b"\x05local");
    assert_eq!(&APPLE_TV_RESPONSE[0x2b..0x37], b"\x0bLiving Room");
    assert_eq!(&APPLE_TV_RESPONSE[0x71..0x7d], b"\x0bLiving-Room");
}

/// The whole point of the codec: turn one real response into the records a scan needs.
#[test]
fn parses_a_realistic_multi_record_response() {
    let message = DnsMessage::unpack(APPLE_TV_RESPONSE).expect("fixture parses");

    assert_eq!(message.msg_id, 0);
    assert_eq!(message.flags, 0x8400);
    assert!(message.header().is_response());
    assert!(message.questions.is_empty());
    assert_eq!(message.answers.len(), 2);
    assert!(message.authorities.is_empty());
    assert_eq!(message.resources.len(), 3);

    // PTR: compression on the RDATA target.
    let ptr = &message.answers[0];
    assert_eq!(ptr.qname, "_airplay._tcp.local");
    assert_eq!(ptr.qtype, QueryType::PTR);
    assert_eq!(ptr.ttl, 4500);
    assert_eq!(
        ptr.rd.as_ptr_name(),
        Some("Living Room._airplay._tcp.local")
    );

    // TXT: compression on the owner name, and a DNS-SD instance label containing a space.
    let txt = &message.answers[1];
    assert_eq!(txt.qname, "Living Room._airplay._tcp.local");
    let properties = txt.rd.as_txt().expect("TXT rdata").decode_properties();
    assert_eq!(properties.get("model").map(String::as_str), Some("J305AP"));
    assert_eq!(properties.get("deviceid").map(String::as_str), Some("001"));

    // SRV: the port a scan must never hardcode, and a target compressed against "local".
    let srv = message.resources[0].rd.as_srv().expect("SRV rdata");
    assert_eq!(srv.port, 7000);
    assert_eq!(srv.target, "Living-Room.local");

    // A and AAAA for the SRV target.
    assert_eq!(message.resources[1].qname, "Living-Room.local");
    assert_eq!(
        message.resources[1].rd,
        RecordData::A(Ipv4Addr::new(192, 168, 1, 40))
    );
    assert_eq!(
        message.resources[2].rd,
        RecordData::Aaaa(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0x0223, 0x32ff, 0xfeb1, 0x2152
        ))
    );

    // The instance name splits back into its DNS-SD parts, dots and spaces intact.
    let instance = crate::dns::ServiceInstanceName::split_name(&txt.qname).expect("service name");
    assert_eq!(instance.instance.as_deref(), Some("Living Room"));
    assert_eq!(instance.ptr_name(), "_airplay._tcp.local");
}

/// Re-encoding with compression and parsing again must yield the same records. The bytes are not
/// asserted to be identical to the fixture: which suffixes a responder chooses to compress is its
/// own business, and only the decoded meaning is contractual.
#[test]
fn a_compressed_response_survives_a_decode_encode_decode_cycle() {
    let original = DnsMessage::unpack(APPLE_TV_RESPONSE).expect("fixture parses");

    let repacked = original.pack_compressed();
    assert!(
        repacked.len() < original.pack().len(),
        "compression should save bytes on a message this repetitive"
    );

    let reparsed = DnsMessage::unpack(&repacked).expect("repacked message parses");
    assert_eq!(reparsed, original);

    // ...and the uncompressed form has to mean the same thing.
    let plain = DnsMessage::unpack(&original.pack()).expect("plain message parses");
    assert_eq!(plain, original);
}

/// pyatv `core/mdns.py::create_service_queries` builds exactly this.
#[test]
fn builds_the_query_pyatv_sends() {
    let message = DnsMessage::query(
        DEFAULT_QUERY_ID,
        [
            "_mediaremotetv._tcp.local",
            "_companion-link._tcp.local",
            "_airplay._tcp.local",
            "_sleep-proxy._udp.local",
        ],
        QueryType::PTR,
    );

    assert_eq!(message.msg_id, 0x35FF);
    assert_eq!(message.flags, DEFAULT_FLAGS);
    assert_eq!(message.questions.len(), 4);
    for question in &message.questions {
        assert_eq!(question.qtype, QueryType::PTR);
        assert_eq!(question.qclass, QCLASS_IN_UNICAST);
        assert!(question.wants_unicast_response());
    }

    let wire = message.pack();
    assert_eq!(
        &wire[..12],
        &[0x35, 0xFF, 0x01, 0x20, 0, 4, 0, 0, 0, 0, 0, 0]
    );

    let parsed = DnsMessage::unpack(&wire).expect("round-trips");
    assert_eq!(parsed, message);
    assert_eq!(parsed.questions[3].qname, "_sleep-proxy._udp.local");
}

/// A query with repeated `_tcp.local` suffixes is where compression pays off, and it has to survive
/// the round trip byte for byte in meaning.
#[test]
fn a_compressed_query_round_trips() {
    let message = DnsMessage::query(
        DEFAULT_QUERY_ID,
        [
            "_mediaremotetv._tcp.local",
            "_companion-link._tcp.local",
            "_airplay._tcp.local",
            "_raop._tcp.local",
            "_touch-able._tcp.local",
        ],
        QueryType::PTR,
    );

    let compressed = message.pack_compressed();
    assert!(compressed.len() < message.pack().len());
    assert_eq!(DnsMessage::unpack(&compressed).unwrap(), message);
}

#[test]
fn headers_round_trip() {
    let header = DnsHeader {
        id: 0x35FF,
        flags: DEFAULT_FLAGS,
        qdcount: 1,
        ancount: 2,
        nscount: 3,
        arcount: 4,
    };
    let packed = header.pack();
    assert_eq!(packed, [0x35, 0xFF, 0x01, 0x20, 0, 1, 0, 2, 0, 3, 0, 4]);
    assert_eq!(
        DnsHeader::unpack(&mut Reader::new(&packed)).unwrap(),
        header
    );
    assert!(!header.is_response());
}

/// The section counts always come from the vectors, so they cannot describe a message that is not
/// there.
#[test]
fn the_header_counts_follow_the_sections() {
    let mut message = DnsMessage::new(1);
    message
        .questions
        .push(DnsQuestion::new("_airplay._tcp.local", QueryType::PTR));
    message.answers.push(DnsResource {
        qname: "_airplay._tcp.local".into(),
        qtype: QueryType::PTR,
        qclass: CLASS_IN,
        ttl: 4500,
        rd: RecordData::Ptr("atv._airplay._tcp.local".into()),
    });
    message.resources.push(DnsResource {
        qname: "atv._airplay._tcp.local".into(),
        qtype: QueryType::SRV,
        qclass: CLASS_IN,
        ttl: 120,
        rd: RecordData::Srv(SrvData {
            priority: 0,
            weight: 0,
            port: 49152,
            target: "atv.local".into(),
        }),
    });

    let header = message.header();
    assert_eq!((header.qdcount, header.ancount), (1, 1));
    assert_eq!((header.nscount, header.arcount), (0, 1));
    assert_eq!(DnsMessage::unpack(&message.pack()).unwrap(), message);
}

#[test]
fn txt_answers_survive_the_pack_that_pyatv_gets_wrong() {
    // pyatv's `DnsMessage.pack` calls `qname_encode(answer.rd)` on every answer, so a TXT answer is
    // mangled into a domain name. Ours encodes by variant, so this round-trips.
    let mut txt = TxtRecords::new();
    txt.insert("model", b"J305AP".to_vec());

    let mut message = DnsMessage::new(0);
    message.answers.push(DnsResource {
        qname: "atv._airplay._tcp.local".into(),
        qtype: QueryType::TXT,
        qclass: CLASS_IN,
        ttl: 4500,
        rd: RecordData::Txt(txt),
    });

    assert_eq!(DnsMessage::unpack(&message.pack()).unwrap(), message);
}

/// Everything a hostile or broken sender can do to a message, none of which may panic.
#[test]
fn malformed_messages_are_rejected_cleanly() {
    // Shorter than the header.
    assert!(matches!(
        DnsMessage::unpack(&[0x00; 11]),
        Err(DnsError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        DnsMessage::unpack(&[]),
        Err(DnsError::UnexpectedEof { .. })
    ));

    // A header claiming 65535 questions in an otherwise empty message: the parser must fail on the
    // first read rather than allocating for a count it was told to expect.
    let liar = [0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        DnsMessage::unpack(&liar),
        Err(DnsError::UnexpectedEof { .. })
    ));

    // ...and the same for each of the other three sections.
    for offset in [6usize, 8, 10] {
        let mut liar = [0x00u8; 12];
        liar[offset] = 0xFF;
        liar[offset + 1] = 0xFF;
        assert!(
            DnsMessage::unpack(&liar).is_err(),
            "section at byte {offset} should fail"
        );
    }

    // An answer whose owner name is a self-referential compression pointer.
    let looping = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
    ];
    assert_eq!(DnsMessage::unpack(&looping), Err(DnsError::CompressionLoop));

    // Truncating the real fixture at every length must never panic.
    for length in 0..APPLE_TV_RESPONSE.len() {
        let _ = DnsMessage::unpack(&APPLE_TV_RESPONSE[..length]);
    }
}

#[test]
fn renders_a_summary() {
    let message = DnsMessage::unpack(APPLE_TV_RESPONSE).unwrap();
    assert_eq!(
        message.to_string(),
        "MsgId=0x0000 Flags=0x8400 Questions=0 Answers=2 Authorities=0 Resources=3"
    );
}
