//! Ported from pyatv `tests/support/test_dns.py::test_parse_rdata`, plus coverage for the question
//! and resource-record framing that pyatv exercises only through `DnsMessage`.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    CLASS_IN, DnsQuestion, DnsResource, QCLASS_IN_UNICAST, QueryType, RecordData, SrvData,
    parse_rdata,
};
use crate::dns::{DnsError, Reader};

/// Decode RDATA out of a standalone buffer, asserting the whole buffer was consumed — which is
/// exactly what pyatv's `test_parse_rdata` asserts with `buffer.tell() == len(data)`.
fn rdata(qtype: QueryType, data: &[u8]) -> RecordData {
    let mut reader = Reader::new(data);
    let parsed = parse_rdata(&mut reader, qtype, data.len()).expect("fixture parses");
    assert_eq!(reader.position(), data.len(), "consumed the whole RDATA");
    parsed
}

/// pyatv `test_parse_rdata`, ids `A`, `PTR`, `TXT`, `SRV`.
#[test]
fn parses_rdata_like_pyatv() {
    assert_eq!(
        rdata(QueryType::A, b"\x0a\x00\x00\x2a"),
        RecordData::A(Ipv4Addr::new(10, 0, 0, 42))
    );

    assert_eq!(
        rdata(QueryType::PTR, b"\x03foo\x07example\x03com\x00"),
        RecordData::Ptr("foo.example.com".into())
    );

    let RecordData::Txt(txt) = rdata(QueryType::TXT, b"\x07foo=bar") else {
        panic!("expected TXT rdata");
    };
    assert_eq!(txt.get("foo").map(Vec::as_slice), Some(&b"bar"[..]));

    assert_eq!(
        rdata(
            QueryType::SRV,
            b"\x00\x0a\x00\x00\x00\x50\x03foo\x07example\x03com\x00"
        ),
        RecordData::Srv(SrvData {
            priority: 10,
            weight: 0,
            port: 80,
            target: "foo.example.com".into(),
        })
    );
}

/// pyatv has no `AAAA` member in `QueryType`, so it hands IPv6 addresses back as raw bytes. We
/// decode them; this is additive, since `core/mdns.py` only ever reads `A` records.
#[test]
fn parses_aaaa_rdata_which_pyatv_leaves_raw() {
    let data = b"\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x23\x32\xff\xfe\xb1\x21\x52";
    assert_eq!(
        rdata(QueryType::AAAA, data),
        RecordData::Aaaa(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0x0223, 0x32ff, 0xfeb1, 0x2152
        ))
    );
}

/// An unhandled type keeps its RDATA verbatim, as pyatv's `parse_rdata` fallback does.
#[test]
fn keeps_unknown_rdata_verbatim() {
    let data = b"\xde\xad\xbe\xef";
    assert_eq!(
        rdata(QueryType::new(0x002F), data),
        RecordData::Other(data.to_vec())
    );
}

/// pyatv raises `ValueError` when an `A` record is not exactly four bytes.
#[test]
fn rejects_an_address_of_the_wrong_length() {
    let mut reader = Reader::new(b"\x0a\x00\x00");
    assert_eq!(
        parse_rdata(&mut reader, QueryType::A, 3),
        Err(DnsError::InvalidAddressLength {
            qtype: QueryType::A,
            expected: 4,
            length: 3,
        })
    );

    let mut reader = Reader::new(b"\x00\x00\x00\x00");
    assert_eq!(
        parse_rdata(&mut reader, QueryType::AAAA, 4),
        Err(DnsError::InvalidAddressLength {
            qtype: QueryType::AAAA,
            expected: 16,
            length: 4,
        })
    );
}

#[test]
fn query_type_keeps_the_pyatv_values_and_renders_a_name() {
    assert_eq!(QueryType::A.value(), 0x01);
    assert_eq!(QueryType::PTR.value(), 0x0C);
    assert_eq!(QueryType::TXT.value(), 0x10);
    assert_eq!(QueryType::AAAA.value(), 0x1C);
    assert_eq!(QueryType::SRV.value(), 0x21);
    assert_eq!(QueryType::ANY.value(), 0xFF);

    assert_eq!(QueryType::SRV.to_string(), "SRV");
    assert_eq!(QueryType::new(0x0063).to_string(), "TYPE99");
    assert_eq!(QueryType::new(0x0063).name(), None);
    // A raw value round-trips onto the named constant.
    assert_eq!(QueryType::new(0x0021), QueryType::SRV);
}

#[test]
fn questions_default_to_the_class_pyatv_sends() {
    let question = DnsQuestion::new("_airplay._tcp.local", QueryType::PTR);
    assert_eq!(question.qclass, QCLASS_IN_UNICAST);
    assert_eq!(question.qclass, 0x8001);
    assert!(question.wants_unicast_response());
    assert_eq!(question.class(), CLASS_IN);

    let multicast = DnsQuestion {
        qclass: CLASS_IN,
        ..question
    };
    assert!(!multicast.wants_unicast_response());
}

#[test]
fn questions_round_trip() {
    let question = DnsQuestion::new("_companion-link._tcp.local", QueryType::PTR);
    let mut wire = Vec::new();
    question.write(None, &mut wire);

    assert_eq!(
        wire,
        b"\x0f_companion-link\x04_tcp\x05local\x00\x00\x0c\x80\x01"
    );

    let mut reader = Reader::new(&wire);
    assert_eq!(DnsQuestion::unpack(&mut reader).unwrap(), question);
    assert_eq!(reader.position(), wire.len());
}

#[test]
fn resources_round_trip_through_every_rdata_variant() {
    let cases = [
        RecordData::A(Ipv4Addr::new(192, 168, 1, 40)),
        RecordData::Aaaa(Ipv6Addr::LOCALHOST),
        RecordData::Ptr("Living Room._airplay._tcp.local".into()),
        RecordData::Srv(SrvData {
            priority: 0,
            weight: 0,
            port: 7000,
            target: "Living-Room.local".into(),
        }),
        RecordData::Other(vec![0x01, 0x02, 0x03]),
    ];

    for rd in cases {
        // The type has to match the payload for the decoder to reproduce it.
        let qtype = match &rd {
            RecordData::A(_) => QueryType::A,
            RecordData::Aaaa(_) => QueryType::AAAA,
            RecordData::Ptr(_) => QueryType::PTR,
            RecordData::Srv(_) => QueryType::SRV,
            RecordData::Txt(_) | RecordData::Other(_) => QueryType::new(0x0042),
        };
        let record = DnsResource {
            qname: "Living-Room.local".into(),
            qtype,
            qclass: CLASS_IN,
            ttl: 4500,
            rd,
        };

        let mut wire = Vec::new();
        record.write(None, &mut wire);
        let mut reader = Reader::new(&wire);
        assert_eq!(
            DnsResource::unpack(&mut reader).expect("round-trips"),
            record
        );
        assert_eq!(reader.position(), wire.len());
    }
}

/// pyatv asserts that RDATA decoding consumed exactly `rd_length` bytes. Asserting on network input
/// is a crash, so it is an error here — and the assertion does fire on real malformed data, because
/// a lying `RDLENGTH` is the cheapest way to desynchronise a parser.
#[test]
fn a_lying_rdlength_is_rejected() {
    // A PTR record claiming 20 bytes of RDATA that actually decodes in 17.
    let wire = b"\x03foo\x00\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x14\x03foo\x07example\x03com\x00";
    let mut reader = Reader::new(wire);
    assert_eq!(
        DnsResource::unpack(&mut reader),
        Err(DnsError::RdataLengthMismatch {
            expected: 20,
            consumed: 17,
        })
    );
}

#[test]
fn a_truncated_resource_record_is_an_error() {
    let mut reader = Reader::new(b"\x03foo\x00\x00\x0c\x00");
    assert!(matches!(
        DnsResource::unpack(&mut reader),
        Err(DnsError::UnexpectedEof { .. })
    ));
}

#[test]
fn record_data_accessors_only_answer_for_their_own_variant() {
    let srv = RecordData::Srv(SrvData {
        priority: 0,
        weight: 0,
        port: 49152,
        target: "atv.local".into(),
    });
    assert_eq!(srv.as_srv().map(|srv| srv.port), Some(49152));
    assert!(srv.as_txt().is_none());
    assert!(srv.as_ptr_name().is_none());
    assert!(srv.as_ip_addr().is_none());

    let a = RecordData::A(Ipv4Addr::new(10, 0, 0, 42));
    assert_eq!(a.as_ip_addr(), Some(Ipv4Addr::new(10, 0, 0, 42).into()));
    assert!(a.as_srv().is_none());

    let ptr = RecordData::Ptr("atv._airplay._tcp.local".into());
    assert_eq!(ptr.as_ptr_name(), Some("atv._airplay._tcp.local"));
}
