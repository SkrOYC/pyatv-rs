//! Functional tests for [`pyatv_mdns::mdns::unicast`], ported from
//! `tests/core/test_mdns_functional.py` and the request/response fixtures in
//! `tests/core/test_mdns.py`.
//!
//! Every test here runs against the fake responder in [`support::fake_udns`] on an ephemeral
//! loopback port, so nothing touches the real network and nothing depends on a device being
//! present.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pyatv_mdns::dns::{DnsMessage, QueryType};
use pyatv_mdns::mdns::{create_service_queries, unicast};
use pyatv_mdns::service::{Response, SLEEP_PROXY_SERVICE};
use support::fake_udns::{
    FakeUdns, Registration, airplay_service, companion_service, create_response, device_service,
    homesharing_service, hscp_service, mrp_service, raop_service, sleep_proxy_service,
};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const SERVICE_NAME: &str = "Kitchen";
const MEDIAREMOTE_SERVICE: &str = "_mediaremotetv._tcp.local";

/// `TEST_SERVICES` from `tests/core/test_mdns_functional.py:22-28`.
fn test_services() -> Vec<Registration> {
    vec![mrp_service(SERVICE_NAME, SERVICE_NAME, "mrp_id", 1234)]
}

fn names(services: &[&str]) -> Vec<String> {
    services.iter().map(|name| (*name).to_owned()).collect()
}

fn generated_names(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("srv{i}._tcp.local")).collect()
}

async fn scan(server: &FakeUdns, services: &[String], timeout: Duration) -> Response {
    unicast(LOCALHOST, services, server.port(), timeout)
        .await
        .expect("a loopback scan cannot fail at the socket layer")
}

/// `test_unicast_has_valid_service`.
#[tokio::test]
async fn a_unicast_scan_finds_the_expected_service() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");

    let response = scan(
        &server,
        &names(&[MEDIAREMOTE_SERVICE]),
        Duration::from_secs(1),
    )
    .await;

    assert_eq!(response.services.len(), 1);
    assert_eq!(response.services[0].service_type, MEDIAREMOTE_SERVICE);
    assert_eq!(response.services[0].name, SERVICE_NAME);
    assert_eq!(response.services[0].port, 1234);
    assert_eq!(response.services[0].address, Some(LOCALHOST));
    assert!(
        !response.deep_sleep,
        "the unicast path never reports deep sleep"
    );
}

/// The MRP fixture's TXT dictionary arrives intact and case-insensitively addressable.
#[tokio::test]
async fn the_mrp_txt_properties_survive_the_round_trip() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");

    let response = scan(
        &server,
        &names(&[MEDIAREMOTE_SERVICE]),
        Duration::from_secs(1),
    )
    .await;
    let properties = &response.services[0].properties;

    assert_eq!(properties.get("Name").map(String::as_str), Some("Kitchen"));
    assert_eq!(
        properties.get("uniqueidentifier").map(String::as_str),
        Some("mrp_id")
    );
    assert_eq!(
        properties.get("SystemBuildVersion").map(String::as_str),
        Some("18M60")
    );
}

/// `test_unicast_multiple_requests`: exactly `ceil(n / 3)` request messages, whatever the
/// slice-window overlap does to their contents.
#[tokio::test]
async fn the_request_count_is_ceil_of_services_over_three() {
    for (service_count, expected_requests) in [(1, 1), (3, 1), (4, 2), (7, 3)] {
        let server = FakeUdns::start(test_services())
            .await
            .expect("the fake responder binds");

        scan(
            &server,
            &generated_names(service_count),
            Duration::from_millis(900),
        )
        .await;

        assert_eq!(
            server.request_count(),
            expected_requests,
            "{service_count} services"
        );
    }
}

/// `test_unicast_resend_if_no_response`: the once-a-second resend loop recovers from a responder
/// that drops the first two requests.
#[tokio::test]
async fn a_dropped_request_is_resent() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");
    server.set_skip_count(2);

    let response = scan(
        &server,
        &names(&[MEDIAREMOTE_SERVICE]),
        Duration::from_secs(3),
    )
    .await;

    assert_eq!(response.services.len(), 1);
    assert_eq!(response.services[0].name, SERVICE_NAME);
    assert_eq!(response.services[0].port, 1234);
}

/// `test_unicast_specific_service`: asking for one exact instance name rather than a service type.
#[tokio::test]
async fn a_specific_instance_can_be_queried_directly() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");

    let response = scan(
        &server,
        &names(&[&format!("{SERVICE_NAME}.{MEDIAREMOTE_SERVICE}")]),
        Duration::from_secs(1),
    )
    .await;

    assert_eq!(response.services.len(), 1);
    assert_eq!(response.services[0].service_type, MEDIAREMOTE_SERVICE);
    assert_eq!(response.services[0].name, SERVICE_NAME);
}

/// `test_unicast_includes_sleep_proxy_service`: every query carries a sleep-proxy question, so a
/// responder that has one answers it without being asked.
#[tokio::test]
async fn the_sleep_proxy_service_is_always_asked_about() {
    let server = FakeUdns::start(vec![
        (
            "_test._tcp.local".to_owned(),
            support::fake_udns::FakeDnsService {
                name: "test".to_owned(),
                addresses: vec![Ipv4Addr::LOCALHOST],
                port: 1234,
                properties: Vec::new(),
                model: None,
            },
        ),
        sleep_proxy_service("sleepy", 5678),
    ])
    .await
    .expect("the fake responder binds");

    let response = scan(
        &server,
        &names(&["_test._tcp.local"]),
        Duration::from_secs(1),
    )
    .await;

    assert_eq!(response.services.len(), 2);
    let proxy = response
        .services
        .iter()
        .find(|service| service.service_type == SLEEP_PROXY_SERVICE)
        .expect("the sleep proxy answered");
    assert_eq!(proxy.name, "sleepy");
    assert_eq!(proxy.port, 5678);
}

/// A responder that answers nothing yields an empty response rather than an error.
#[tokio::test]
async fn a_missing_service_yields_an_empty_response() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");

    let response = scan(
        &server,
        &names(&["_missing._tcp.local"]),
        Duration::from_millis(900),
    )
    .await;

    assert!(response.services.is_empty());
    assert_eq!(response.model, None);
}

/// `test_multicast_device_model`'s assertion, reached through the unicast path: the model is the
/// raw TXT string synthesised from a fixture's `model=` argument.
#[tokio::test]
async fn the_model_is_read_from_the_device_info_record() {
    let server = FakeUdns::start(vec![airplay_service("Kitchen", "AA:BB:CC:DD:EE:FF", None)])
        .await
        .expect("the fake responder binds");

    let without_model = scan(
        &server,
        &names(&["_airplay._tcp.local"]),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(without_model.model, None);

    server.set_services(vec![airplay_service(
        "Kitchen",
        "AA:BB:CC:DD:EE:FF",
        Some("dummy"),
    )]);
    let with_model = scan(
        &server,
        &names(&["_airplay._tcp.local"]),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(with_model.model.as_deref(), Some("dummy"));
}

/// A responder acting as a sleep proxy answers only a bare `PTR`, which parses to the placeholder
/// shape: no address, port zero, no properties.
#[tokio::test]
async fn a_sleep_proxied_service_comes_back_as_a_placeholder() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");
    server.set_sleep_proxy(true);

    let response = scan(
        &server,
        &names(&[MEDIAREMOTE_SERVICE]),
        Duration::from_secs(1),
    )
    .await;

    assert_eq!(response.services.len(), 1);
    assert_eq!(response.services[0].service_type, MEDIAREMOTE_SERVICE);
    assert_eq!(response.services[0].port, 0);
    assert_eq!(response.services[0].address, None);
    assert!(response.services[0].properties.is_empty());
}

/// `ip_filter` suppresses services that do not advertise the requested address, which is how
/// upstream fakes a per-host multicast scan on loopback.
#[tokio::test]
async fn the_responders_ip_filter_suppresses_non_matching_services() {
    let server = FakeUdns::start(test_services())
        .await
        .expect("the fake responder binds");
    server.set_ip_filter(Some(Ipv4Addr::new(10, 0, 0, 1)));

    let response = scan(
        &server,
        &names(&[MEDIAREMOTE_SERVICE]),
        Duration::from_millis(900),
    )
    .await;

    assert!(response.services.is_empty());
}

/// Every fixture generator produces a service the client can actually find, which guards the
/// TXT dictionaries copied verbatim from `fake_udns.py`.
#[tokio::test]
async fn every_fixture_generator_round_trips() {
    let fixtures: Vec<(Registration, &str)> = vec![
        (
            mrp_service("Kitchen", "Kitchen", "mrp_id", 49152),
            "Kitchen",
        ),
        (
            airplay_service("Kitchen", "AA:BB:CC:DD:EE:FF", None),
            "Kitchen",
        ),
        (
            homesharing_service("Kitchen", "Kitchen", "hsgid"),
            "Kitchen",
        ),
        (device_service("Kitchen", "Kitchen"), "Kitchen"),
        (companion_service("Kitchen", 1234), "Kitchen"),
        (
            raop_service("Kitchen", "AABBCCDDEEFF", 1234),
            "AABBCCDDEEFF@Kitchen",
        ),
        (
            hscp_service("Kitchen", "hscp_id", "hsgid", 1234),
            "HSCP Name",
        ),
    ];

    for (registration, expected_name) in fixtures {
        let service_type = registration.0.clone();
        let server = FakeUdns::start(vec![registration])
            .await
            .expect("the fake responder binds");

        let response = scan(&server, &names(&[&service_type]), Duration::from_secs(1)).await;

        assert_eq!(response.services.len(), 1, "{service_type}");
        assert_eq!(response.services[0].service_type, service_type);
        assert_eq!(response.services[0].name, expected_name, "{service_type}");
    }
}

/// `tests/core/test_mdns.py:44-55`: the shape of the fake responder's answer for a hit and a miss.
#[test]
fn the_fake_responder_answers_the_expected_record_counts() {
    let services = test_services().into_iter().collect();

    let hit = create_service_queries(&names(&[MEDIAREMOTE_SERVICE]), QueryType::PTR);
    let hit = create_response(&hit[0].pack(), &services, None, false);
    assert_eq!(hit.questions.len(), 2, "the service plus the sleep proxy");
    assert_eq!(hit.answers.len(), 1, "one PTR");
    assert_eq!(hit.resources.len(), 3, "SRV, A and TXT");

    let miss = create_service_queries(&names(&["_missing"]), QueryType::PTR);
    let miss = create_response(&miss[0].pack(), &services, None, false);
    assert_eq!(miss.questions.len(), 2);
    assert_eq!(miss.answers.len(), 0);
    assert_eq!(miss.resources.len(), 0);
}

/// `tests/core/test_mdns.py:57-115`: the individual records the fake responder emits.
#[test]
fn the_fake_responders_records_match_the_fixture() {
    let services = test_services().into_iter().collect();
    let query = create_service_queries(&names(&[MEDIAREMOTE_SERVICE]), QueryType::PTR);
    let response = create_response(&query[0].pack(), &services, None, false);
    let response = DnsMessage::unpack(&response.pack()).expect("the response round-trips");

    let full_name = format!("{SERVICE_NAME}.{MEDIAREMOTE_SERVICE}");

    let answer = &response.answers[0];
    assert_eq!(answer.qname, MEDIAREMOTE_SERVICE);
    assert_eq!(answer.qtype, QueryType::PTR);
    assert_eq!(answer.qclass, support::dns_utils::DEFAULT_QCLASS);
    assert_eq!(answer.ttl, support::dns_utils::DEFAULT_TTL);
    assert_eq!(answer.rd.as_ptr_name(), Some(full_name.as_str()));

    let srv = response
        .resources
        .iter()
        .find(|record| record.qtype == QueryType::SRV)
        .expect("an SRV record was emitted");
    let srv_data = srv.rd.as_srv().expect("SRV rdata decodes");
    assert_eq!(srv.qname, full_name);
    assert_eq!(srv_data.priority, 0);
    assert_eq!(srv_data.weight, 0);
    assert_eq!(srv_data.port, 1234);
    assert_eq!(srv_data.target, format!("{SERVICE_NAME}.local"));

    let a = response
        .resources
        .iter()
        .find(|record| record.qtype == QueryType::A)
        .expect("an A record was emitted");
    assert_eq!(a.qname, format!("{SERVICE_NAME}.local"));
    assert_eq!(a.rd.as_ip_addr(), Some(LOCALHOST));

    let txt = response
        .resources
        .iter()
        .find(|record| record.qtype == QueryType::TXT)
        .expect("a TXT record was emitted");
    assert_eq!(txt.qname, full_name);
    let txt_data = txt.rd.as_txt().expect("TXT rdata decodes");
    assert_eq!(txt_data.len(), 3);
    assert_eq!(
        txt_data.get("Name").map(Vec::as_slice),
        Some(&b"Kitchen"[..])
    );
}
