//! The `PTR`-placeholder second pass, the ignored sections, and model extraction.
//!
//! Ported from `tests/core/test_mdns.py` and `test_mdns_functional.py`'s model assertions.

use std::net::{IpAddr, Ipv4Addr};

use super::{ServiceParser, message_with, parse_services, resource};
use crate::dns::{DEFAULT_QUERY_ID, DnsMessage, RecordData, SrvData};
use crate::mdns::parser::get_model;
use crate::service::DEVICE_INFO_SERVICE;

/// A bare `PTR` with no `SRV`/`A`/`TXT` behind it — what a sleep proxy answers with — becomes a
/// placeholder with no address, port zero and no properties (`pyatv/core/mdns.py:163-167`).
#[test]
fn a_ptr_with_no_detail_records_becomes_a_placeholder() {
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    message.answers.push(resource(
        "_abc._tcp.local",
        RecordData::Ptr("Kitchen._abc._tcp.local".to_owned()),
    ));

    let parsed = parse_services(&message);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].service_type, "_abc._tcp.local");
    assert_eq!(parsed[0].name, "Kitchen");
    assert_eq!(parsed[0].address, None);
    assert_eq!(parsed[0].port, 0);
    assert!(parsed[0].properties.is_empty());
}

/// The placeholder path splits naively on the first dot, so a dotted instance name is truncated.
/// Upstream does the same; reproduced so the divergence stays visible if it is ever fixed there.
#[test]
fn the_placeholder_path_truncates_a_dotted_instance_name() {
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    message.answers.push(resource(
        "_abc._tcp.local",
        RecordData::Ptr("Living.Room._abc._tcp.local".to_owned()),
    ));

    let parsed = parse_services(&message);
    assert_eq!(parsed[0].name, "Living");
}

/// A `PTR` whose instance already produced a real service does not also produce a placeholder.
#[test]
fn a_ptr_backed_by_detail_records_produces_one_service() {
    let message = message_with(
        Some("_abc._tcp.local"),
        Some("service"),
        &["10.0.10.1"],
        123,
        &[],
    );
    assert_eq!(message.answers.len(), 1);
    assert_eq!(parse_services(&message).len(), 1);
}

/// A `PTR` whose owner name does not start with `_` is filed as an ordinary record, not as
/// service-type bookkeeping — and then skipped, since it is not a service instance name.
#[test]
fn a_ptr_not_owned_by_a_service_type_is_not_bookkeeping() {
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    message.answers.push(resource(
        "1.0.0.10.in-addr.arpa",
        RecordData::Ptr("Kitchen.local".to_owned()),
    ));

    let mut parser = ServiceParser::new();
    parser.add_message(&message);
    assert_eq!(
        parser.owner_names().collect::<Vec<_>>(),
        ["1.0.0.10.in-addr.arpa"]
    );
    assert!(parser.parse().is_empty());
}

/// Records spread across two datagrams still resolve — that is the whole point of the two phases.
#[test]
fn records_accumulate_across_messages() {
    let mut srv_only = DnsMessage::new(DEFAULT_QUERY_ID);
    srv_only.resources.push(resource(
        "service._abc._tcp.local",
        RecordData::Srv(SrvData {
            priority: 0,
            weight: 0,
            port: 4321,
            target: "service.local".to_owned(),
        }),
    ));

    let mut a_only = DnsMessage::new(DEFAULT_QUERY_ID);
    a_only.resources.push(resource(
        "service.local",
        RecordData::A(Ipv4Addr::new(10, 0, 0, 5)),
    ));

    let mut parser = ServiceParser::new();
    parser.add_message(&srv_only);
    assert_eq!(parser.parse()[0].address, None);

    parser.add_message(&a_only);
    let parsed = parser.parse();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].port, 4321);
    assert_eq!(
        parsed[0].address,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
    );
}

/// The authority section is never consulted (`pyatv/core/mdns.py:118`).
#[test]
fn the_authority_section_is_ignored() {
    let mut message = message_with(Some("_abc._tcp.local"), Some("service"), &[], 0, &[]);
    message.authorities = std::mem::take(&mut message.resources);
    message.answers.clear();

    assert!(parse_services(&message).is_empty());
}

/// `_get_model` reads the raw `model` string off `_device-info._tcp.local` and nothing else.
#[test]
fn the_model_comes_from_the_device_info_service() {
    let message = message_with(
        Some(DEVICE_INFO_SERVICE),
        Some("Kitchen"),
        &[],
        0,
        &[("model", "J105aAP")],
    );
    let services = parse_services(&message);

    assert_eq!(get_model(&services).as_deref(), Some("J105aAP"));
}

/// No `_device-info._tcp.local` service means no model, even if some other service has a `model`
/// property of its own.
#[test]
fn no_device_info_service_means_no_model() {
    let message = message_with(
        Some("_airplay._tcp.local"),
        Some("Kitchen"),
        &[],
        7000,
        &[("model", "AppleTV6,2")],
    );
    let services = parse_services(&message);

    assert_eq!(get_model(&services), None);
}

/// `response()` folds the parsed services and the model into one `Response`.
#[test]
fn a_response_carries_the_services_the_model_and_the_deep_sleep_flag() {
    let message = message_with(
        Some(DEVICE_INFO_SERVICE),
        Some("Kitchen"),
        &[],
        0,
        &[("model", "dummy")],
    );

    let mut parser = ServiceParser::new();
    parser.add_message(&message);

    let response = parser.response(true);
    assert_eq!(response.services.len(), 1);
    assert_eq!(response.model.as_deref(), Some("dummy"));
    assert!(response.deep_sleep);
}
