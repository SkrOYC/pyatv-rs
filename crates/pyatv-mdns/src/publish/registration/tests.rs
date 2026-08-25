//! Wire-format tests for the responder's sans-io half.
//!
//! Everything here asserts on bytes or on decoded records, never on internal structure: the point
//! of the module is what a browsing Apple TV sees.

use std::net::Ipv4Addr;

use super::{
    CACHE_FLUSH, GOODBYE_TTL, HOST_TTL, LEGACY_UNICAST_TTL, RESPONSE_FLAGS, SERVICE_TTL,
    ServiceRegistration,
};
use crate::dns::{CLASS_IN, DnsMessage, DnsQuestion, QCLASS_IN_UNICAST, QueryType, RecordData};

const SERVICE_TYPE: &str = "_touch-remote._tcp.local";
const INSTANCE: &str = "0000000000000000000000000000000167774977";
const HOST: &str = "pyatv-rs.local";

fn registration() -> ServiceRegistration {
    ServiceRegistration::new(SERVICE_TYPE, INSTANCE, HOST, 49_152)
        .with_address(Ipv4Addr::new(10, 0, 10, 1))
        .with_property("DvNm", "pyatv remote")
        .with_property("RemV", "10000")
        .with_property("DvTy", "iPod")
        .with_property("RemN", "Remote")
        .with_property("txtvers", "1")
        .with_property("Pair", "0000000000000001")
}

fn question(name: &str, qtype: QueryType) -> DnsQuestion {
    DnsQuestion {
        qname: name.to_owned(),
        qtype,
        qclass: CLASS_IN,
    }
}

/// The exact TXT payload pyatv's six properties produce. Key case is load-bearing: a device
/// browsing for `_touch-remote._tcp` looks for `DvNm`, not `dvnm`.
#[test]
fn txt_rdata_preserves_key_case_and_order() {
    let rdata = registration().txt_rdata();

    let mut expected = Vec::new();
    for chunk in [
        "DvNm=pyatv remote",
        "RemV=10000",
        "DvTy=iPod",
        "RemN=Remote",
        "txtvers=1",
        "Pair=0000000000000001",
    ] {
        expected.push(u8::try_from(chunk.len()).expect("test chunks are short"));
        expected.extend_from_slice(chunk.as_bytes());
    }

    assert_eq!(rdata, expected);
}

/// RFC 6763 §6.1: TXT RDATA is never zero-length; a property-less service sends one empty string.
#[test]
fn an_empty_property_set_still_encodes_one_byte() {
    let bare = ServiceRegistration::new(SERVICE_TYPE, INSTANCE, HOST, 1);
    assert_eq!(bare.txt_rdata(), vec![0u8]);
}

/// PTR is shared, so it must not carry the cache-flush bit; the other three are unique and must.
#[test]
fn only_unique_records_carry_the_cache_flush_bit() {
    let registration = registration();

    assert_eq!(registration.ptr_record(SERVICE_TTL).qclass, CLASS_IN);
    for record in [
        registration.srv_record(HOST_TTL),
        registration.txt_record(SERVICE_TTL),
    ] {
        assert_eq!(record.qclass, CLASS_IN | CACHE_FLUSH, "{record:?}");
    }
    for record in registration.address_records(HOST_TTL) {
        assert_eq!(record.qclass, CLASS_IN | CACHE_FLUSH);
    }
}

/// A `PTR` browse gets the instance plus everything needed to connect, RFC 6763 §12.
#[test]
fn a_browse_is_answered_with_the_full_instance() {
    let registration = registration();
    let answer = registration.answer(&question(SERVICE_TYPE, QueryType::PTR), None);

    assert_eq!(answer.answers.len(), 1);
    assert_eq!(
        answer.answers[0].rd.as_ptr_name(),
        Some(registration.instance_name().as_str())
    );

    let types: Vec<_> = answer.additionals.iter().map(|it| it.qtype).collect();
    assert_eq!(
        types,
        vec![QueryType::SRV, QueryType::TXT, QueryType::A],
        "a browsing client should need no follow-up query"
    );
}

/// The SRV record carries the ephemeral port the pairing server actually bound.
#[test]
fn the_srv_record_carries_the_bound_port() {
    let registration = registration();
    let answer = registration.answer(
        &question(&registration.instance_name(), QueryType::SRV),
        None,
    );

    let srv = answer.answers[0].rd.as_srv().expect("SRV was asked for");
    assert_eq!(srv.port, 49_152);
    assert_eq!(srv.target, HOST);
    assert_eq!((srv.priority, srv.weight), (0, 0));
    assert_eq!(
        answer.additionals.len(),
        1,
        "an SRV answer carries the target's address"
    );
}

/// `ANY` is what pyatv re-queries a sleep proxy with, and a responder has to answer it.
#[test]
fn any_matches_every_record_for_a_name() {
    let registration = registration();
    let answer = registration.answer(
        &question(&registration.instance_name(), QueryType::ANY),
        None,
    );

    let types: Vec<_> = answer.answers.iter().map(|it| it.qtype).collect();
    assert_eq!(types, vec![QueryType::SRV, QueryType::TXT]);
}

/// DNS names are case-insensitive, and a trailing root dot is optional in this crate's names.
#[test]
fn name_matching_ignores_case_and_a_trailing_dot() {
    let registration = registration();

    for name in [
        "_TOUCH-REMOTE._TCP.LOCAL",
        "_touch-remote._tcp.local.",
        "_Touch-Remote._tcp.local",
    ] {
        assert!(
            !registration
                .answer(&question(name, QueryType::PTR), None)
                .is_empty(),
            "{name} should match"
        );
    }
}

/// Someone else's service type is not ours to answer.
#[test]
fn an_unrelated_question_is_not_answered() {
    let registration = registration();

    for (name, qtype) in [
        ("_airplay._tcp.local", QueryType::PTR),
        ("some-other-host.local", QueryType::A),
        (SERVICE_TYPE, QueryType::A),
    ] {
        assert!(
            registration.answer(&question(name, qtype), None).is_empty(),
            "{name}/{qtype} should not be answered"
        );
    }
}

/// A response is `QR|AA`, carries no questions, and uses ID zero (RFC 6762 §18).
#[test]
fn a_multicast_response_has_no_questions_and_a_zero_id() {
    let query = DnsMessage::query(0x35FF, [SERVICE_TYPE], QueryType::PTR);
    let response = registration()
        .respond(&query, false)
        .expect("our own service type is answered");

    assert_eq!(response.msg_id, 0);
    assert_eq!(response.flags, RESPONSE_FLAGS);
    assert!(response.questions.is_empty());
    assert!(response.header().is_response());
    assert_eq!(response.answers[0].ttl, SERVICE_TTL);
}

/// RFC 6762 §6.7: a legacy resolver gets its ID and question back, and short TTLs.
#[test]
fn a_legacy_unicast_response_echoes_the_query() {
    let query = DnsMessage::query(0x35FF, [SERVICE_TYPE], QueryType::PTR);
    let response = registration()
        .respond(&query, true)
        .expect("our own service type is answered");

    assert_eq!(response.msg_id, 0x35FF);
    assert_eq!(response.questions, query.questions);
    for record in response.answers.iter().chain(&response.resources) {
        assert!(
            record.ttl <= LEGACY_UNICAST_TTL,
            "{record:?} exceeds the legacy TTL cap"
        );
    }
}

/// A response is never answered, only queries are — otherwise two responders would loop forever.
#[test]
fn a_response_is_never_responded_to() {
    let announcement = registration().announcement();
    assert!(registration().respond(&announcement, false).is_none());
}

/// pyatv's own scanner sets the QU bit on every question, so this is the common path.
#[test]
fn the_qu_bit_is_honoured_only_for_questions_we_answer() {
    let registration = registration();

    let ours = DnsMessage::query(1, [SERVICE_TYPE], QueryType::PTR);
    assert_eq!(ours.questions[0].qclass, QCLASS_IN_UNICAST);
    assert!(registration.wants_unicast(&ours));

    let theirs = DnsMessage::query(1, ["_airplay._tcp.local"], QueryType::PTR);
    assert!(
        !registration.wants_unicast(&theirs),
        "a QU question about someone else's service is not ours to unicast"
    );

    let multicast_wanted = DnsMessage {
        questions: vec![question(SERVICE_TYPE, QueryType::PTR)],
        ..DnsMessage::new(1)
    };
    assert!(!registration.wants_unicast(&multicast_wanted));
}

/// One record must not appear in both sections, and two questions must not duplicate it.
#[test]
fn overlapping_questions_do_not_duplicate_records() {
    let registration = registration();
    let query = DnsMessage {
        questions: vec![
            question(SERVICE_TYPE, QueryType::PTR),
            question(&registration.instance_name(), QueryType::SRV),
            question(HOST, QueryType::A),
        ],
        ..DnsMessage::new(7)
    };

    let response = registration
        .respond(&query, false)
        .expect("all three questions are ours");

    let mut all: Vec<_> = response
        .answers
        .iter()
        .chain(&response.resources)
        .cloned()
        .collect();
    let before = all.len();
    all.dedup();
    assert_eq!(before, all.len(), "records repeat across sections");
    assert_eq!(all.len(), 4, "PTR, SRV, TXT and one A");
}

/// The goodbye is the same record set with a zero TTL, RFC 6762 §10.1.
#[test]
fn the_goodbye_zeroes_every_ttl() {
    let goodbye = registration().goodbye();

    assert_eq!(goodbye.flags, RESPONSE_FLAGS);
    assert_eq!(goodbye.answers.len(), 4);
    for record in &goodbye.answers {
        assert_eq!(record.ttl, GOODBYE_TTL, "{record:?}");
    }
}

/// The whole point: a response has to survive a round trip through this crate's own decoder, since
/// that is what pyatv's scanner does to it.
#[test]
fn a_response_round_trips_through_the_decoder() {
    let query = DnsMessage::query(0x35FF, [SERVICE_TYPE], QueryType::PTR);
    let wire = registration()
        .respond(&query, false)
        .expect("answered")
        .pack();

    let decoded = DnsMessage::unpack(&wire).expect("our own encoder produces decodable bytes");
    assert!(decoded.header().is_response());
    assert_eq!(
        decoded.answers[0].rd.as_ptr_name(),
        Some(format!("{INSTANCE}.{SERVICE_TYPE}").as_str())
    );

    let txt = decoded
        .resources
        .iter()
        .find(|it| it.qtype == QueryType::TXT)
        .expect("TXT is an additional");
    let RecordData::Txt(properties) = &txt.rd else {
        panic!("TXT RDATA should decode as TXT");
    };
    // The decoder lowercases keys, as pyatv's `CaseInsensitiveDict` does; the *bytes* kept their
    // case, which is what `txt_rdata_preserves_key_case_and_order` pins down.
    assert_eq!(
        properties.get("dvnm").map(Vec::as_slice),
        Some(b"pyatv remote".as_slice())
    );
    assert_eq!(
        properties.get("pair").map(Vec::as_slice),
        Some(b"0000000000000001".as_slice())
    );

    let srv = decoded
        .resources
        .iter()
        .find_map(|it| it.rd.as_srv())
        .expect("SRV is an additional");
    assert_eq!(srv.port, 49_152);
}
