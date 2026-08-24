//! Parsing of the ordinary case: `SRV`/`A`/`TXT` records behind a `PTR`.
//!
//! Ported from `tests/core/test_mdns.py`.

use std::net::{IpAddr, Ipv4Addr};

use super::{ServiceParser, add_service, assert_service, message_with, parse_services};

use crate::dns::{DEFAULT_QUERY_ID, DnsMessage, QueryType};

/// `test_parse_empty_service`.
#[test]
fn an_empty_message_yields_no_services() {
    assert!(parse_services(&DnsMessage::new(DEFAULT_QUERY_ID)).is_empty());
}

/// `test_parse_no_service_name`: no name means no records at all were added.
#[test]
fn a_service_without_a_name_yields_nothing() {
    let message = message_with(Some("_abc._tcp.local"), None, &["10.0.0.1"], 123, &[]);
    assert!(parse_services(&message).is_empty());
}

/// `test_parse_no_service_type`: an `A` record under a plain host name is not a service instance,
/// so `ServiceInstanceName::split_name` rejects it and the record is skipped silently.
#[test]
fn a_record_under_a_non_service_name_is_skipped() {
    let message = message_with(None, Some("service"), &["10.0.0.1"], 0, &[]);
    assert_eq!(message.resources.len(), 1);
    assert!(parse_services(&message).is_empty());
}

/// `test_parse_with_name_and_type`: no `A` record and port zero still produces a service.
#[test]
fn a_type_and_a_name_are_enough() {
    let message = message_with(Some("_abc._tcp.local"), Some("service"), &[], 0, &[]);
    let parsed = parse_services(&message);

    assert_eq!(parsed.len(), 1);
    assert_service(&parsed[0], "_abc._tcp.local", "service", &[], 0, &[]);
}

/// `test_parse_with_port_and_address`.
#[test]
fn the_srv_port_and_the_a_record_address_are_threaded_through() {
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &["10.0.0.1"],
        123,
        &[],
    );
    let parsed = parse_services(&message);

    assert_eq!(parsed.len(), 1);
    assert_service(
        &parsed[0],
        "_abc._tcp.local",
        "service",
        &["10.0.0.1"],
        123,
        &[],
    );
}

/// `test_parse_single_service`.
#[test]
fn a_full_service_round_trips() {
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &["10.0.10.1"],
        123,
        &[("foo", "bar")],
    );
    let parsed = parse_services(&message);

    assert_eq!(parsed.len(), 1);
    assert_service(
        &parsed[0],
        "_abc._tcp.local",
        "service",
        &["10.0.10.1"],
        123,
        &[("foo", "bar")],
    );
}

/// `test_parse_double_service`, which asserts on the *order* services come back in.
#[test]
fn two_services_come_back_in_arrival_order() {
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    add_service(
        &mut message,
        Some("_abc._tcp.local"),
        Some("service1"),
        &["10.0.10.1"],
        123,
        &[("foo", "bar")],
    );
    add_service(
        &mut message,
        Some("_def._tcp.local"),
        Some("service2"),
        &["10.0.10.2"],
        456,
        &[("fizz", "buzz")],
    );

    let parsed = parse_services(&message);
    assert_eq!(parsed.len(), 2);
    assert_service(
        &parsed[0],
        "_abc._tcp.local",
        "service1",
        &["10.0.10.1"],
        123,
        &[("foo", "bar")],
    );
    assert_service(
        &parsed[1],
        "_def._tcp.local",
        "service2",
        &["10.0.10.2"],
        456,
        &[("fizz", "buzz")],
    );
}

/// `test_parse_pick_one_available_address` asserts membership, not an index — upstream does not
/// promise which of several routable addresses wins, so neither does this test.
#[test]
fn one_of_several_routable_addresses_is_picked() {
    let addresses = ["10.0.10.1", "10.0.10.2"];
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &addresses,
        123,
        &[("foo", "bar")],
    );

    let parsed = parse_services(&message);
    assert_eq!(parsed.len(), 1);
    let address = parsed[0].address.expect("a routable address was answered");
    assert!(
        addresses
            .iter()
            .any(|candidate| candidate.parse::<IpAddr>() == Ok(address)),
        "{address} is not one of {addresses:?}"
    );
}

/// `test_parse_ignore_link_local_address`: 169.254/16 never wins, and there is no fallback.
#[test]
fn a_link_local_only_service_has_no_address() {
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &["169.254.1.1"],
        123,
        &[("foo", "bar")],
    );

    let parsed = parse_services(&message);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].address, None);
}

/// A link-local address does not shadow a routable one listed after it.
#[test]
fn a_link_local_address_is_skipped_in_favour_of_a_routable_one() {
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &["169.254.1.1", "10.0.10.1"],
        123,
        &[],
    );

    let parsed = parse_services(&message);
    assert_eq!(
        parsed[0].address,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 10, 1)))
    );
}

/// `test_parse_properties_converts_keys_to_lower_case`, with upstream's own comment: this is an
/// unwanted side effect of the case-insensitive map, kept so a future change cannot silently
/// alter it.
#[test]
fn property_keys_are_matched_case_insensitively() {
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &[],
        0,
        &[("FOO", "bar"), ("Bar", "FOO")],
    );

    let parsed = parse_services(&message);
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].properties.get("foo").map(String::as_str),
        Some("bar")
    );
    assert_eq!(
        parsed[0].properties.get("Bar").map(String::as_str),
        Some("FOO")
    );
}

/// `test_parse_ignore_duplicate_records`: resending a query must not double the stored records.
#[test]
fn byte_identical_duplicate_records_are_dropped() {
    let message = message_with(Some("_abc._tcp.local"), Some("service"), &[], 0, &[]);

    let mut parser = ServiceParser::new();
    parser.add_message(&message);
    parser.add_message(&message);

    assert_eq!(parser.owner_names().count(), 1);
    assert_eq!(
        parser
            .records("service._abc._tcp.local", QueryType::SRV)
            .count(),
        1
    );
    assert_eq!(parser.parse().len(), 1);
}
