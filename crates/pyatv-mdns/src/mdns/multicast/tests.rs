//! Unit tests for the sans-io half of the multicast scan.
//!
//! Correlation, foreign-service filtering, deep-sleep detection and the early stop are all
//! exercised by feeding [`MulticastState`] datagrams directly. Real multicast is not involved: it
//! needs a cooperating link, and CI runners routinely have none. The socket plumbing gets one
//! `#[ignore]`d integration test instead — see `tests/multicast_browse.rs`.

use std::net::{IpAddr, Ipv4Addr};

use super::{Handled, MulticastState};
use crate::dns::{DEFAULT_QUERY_ID, DnsMessage, DnsResource, QueryType, RecordData, SrvData};
use crate::service::{DEVICE_INFO_SERVICE, Response, SLEEP_PROXY_SERVICE};

const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
const OTHER_SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
const MRP: &str = "_mediaremotetv._tcp.local";

fn record(qname: &str, qtype: QueryType, rd: RecordData) -> DnsResource {
    DnsResource {
        qname: qname.to_owned(),
        qtype,
        qclass: 1,
        ttl: 10,
        rd,
    }
}

/// A full answer for one service: PTR, SRV and A, the shape a responding device sends.
fn answer_for(service_type: &str, name: &str, port: u16, address: Ipv4Addr) -> Vec<u8> {
    let full_name = format!("{name}.{service_type}");
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    message.answers.push(record(
        service_type,
        QueryType::PTR,
        RecordData::Ptr(full_name.clone()),
    ));
    message.resources.push(record(
        &full_name,
        QueryType::SRV,
        RecordData::Srv(SrvData {
            priority: 0,
            weight: 0,
            port,
            target: format!("{name}.local"),
        }),
    ));
    message.resources.push(record(
        &format!("{name}.local"),
        QueryType::A,
        RecordData::A(address),
    ));
    message.pack()
}

/// A sleep proxy's answer: a bare PTR, nothing behind it.
fn ptr_only(service_type: &str, name: &str) -> Vec<u8> {
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    message.answers.push(record(
        service_type,
        QueryType::PTR,
        RecordData::Ptr(format!("{name}.{service_type}")),
    ));
    message.pack()
}

fn state(query_count: usize) -> MulticastState {
    MulticastState::new(&[MRP.to_owned()], query_count)
}

/// A response for a requested service type is folded into that source's state.
#[test]
fn a_wanted_service_is_accumulated() {
    let mut state = state(1);
    let datagram = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));

    assert_eq!(
        state.handle(SOURCE, &datagram, None),
        Handled::Accumulated,
        "no end condition means the scan keeps running"
    );

    let responses = state.into_responses();
    assert_eq!(responses.len(), 1);
    let response = &responses[&SOURCE];
    assert_eq!(response.services.len(), 1);
    assert_eq!(response.services[0].service_type, MRP);
    assert_eq!(response.services[0].port, 49152);
    assert!(!response.deep_sleep);
}

/// One unrequested service type discards the whole datagram, not just that service.
#[test]
fn one_foreign_service_drops_the_entire_datagram() {
    let mut state = state(1);
    let mut message = DnsMessage::unpack(&answer_for(
        MRP,
        "Kitchen",
        49152,
        Ipv4Addr::new(10, 0, 0, 10),
    ))
    .expect("fixture round-trips");
    message.answers.push(record(
        "_printer._tcp.local",
        QueryType::PTR,
        RecordData::Ptr("Office._printer._tcp.local".to_owned()),
    ));

    assert_eq!(
        state.handle(SOURCE, &message.pack(), None),
        Handled::Ignored
    );
    assert!(state.into_responses()[&SOURCE].services.is_empty());
}

/// `_device-info._tcp.local` and `_sleep-proxy._udp.local` are always implicitly wanted.
#[test]
fn the_two_implicit_service_types_are_never_foreign() {
    for service_type in [DEVICE_INFO_SERVICE, SLEEP_PROXY_SERVICE] {
        let mut state = state(1);
        let datagram = answer_for(service_type, "Kitchen", 1234, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(
            state.handle(SOURCE, &datagram, None),
            Handled::Accumulated,
            "{service_type} should be implicitly requested"
        );
    }
}

/// Every service reporting port zero is the deep-sleep signal, and it is sticky.
#[test]
fn an_all_port_zero_response_flags_deep_sleep() {
    let mut state = state(2);
    assert_eq!(
        state.handle(SOURCE, &ptr_only(MRP, "Kitchen"), None),
        Handled::Accumulated
    );

    let awake = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));
    assert_eq!(state.handle(SOURCE, &awake, None), Handled::Accumulated);

    let responses = state.into_responses();
    assert!(
        responses[&SOURCE].deep_sleep,
        "deep_sleep is OR-accumulated and never clears"
    );
}

/// A normally-responding host is not flagged as asleep.
#[test]
fn a_responding_host_is_not_flagged_deep_sleep() {
    let mut state = state(1);
    let datagram = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));
    state.handle(SOURCE, &datagram, None);

    assert!(!state.into_responses()[&SOURCE].deep_sleep);
}

/// A sleeping host gets a targeted `ANY` re-query queued, but not sent immediately.
#[test]
fn a_sleeping_host_queues_a_unicast_follow_up() {
    let mut state = state(1);
    state.handle(SOURCE, &ptr_only(MRP, "Kitchen"), None);

    let pending = state.pending_unicasts();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, SOURCE);

    let query = DnsMessage::unpack(&pending[0].1[0]).expect("the queued query is a DNS message");
    assert_eq!(query.questions[0].qname, format!("Kitchen.{MRP}"));
    assert_eq!(
        query.questions[0].qtype,
        QueryType::ANY,
        "the follow-up asks for ANY, not PTR"
    );
    assert_eq!(query.questions[1].qname, SLEEP_PROXY_SERVICE);
}

/// A responding (non-sleeping) host queues nothing.
#[test]
fn an_awake_host_queues_no_follow_up() {
    let mut state = state(1);
    let datagram = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));
    state.handle(SOURCE, &datagram, None);

    assert!(state.pending_unicasts().is_empty());
}

/// The end condition only runs once a source has sent as many datagrams as there were queries.
#[test]
fn the_end_condition_waits_for_the_query_count() {
    let mut state = state(2);
    // `Cell` would be simpler but the end condition must be `Send + Sync` to cross a socket task.
    let called = std::sync::atomic::AtomicU32::new(0);
    let end_condition = |_: &Response| {
        called.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    };
    let count = || called.load(std::sync::atomic::Ordering::Relaxed);

    let first = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));
    assert_eq!(
        state.handle(SOURCE, &first, Some(&end_condition)),
        Handled::Accumulated
    );
    assert_eq!(count(), 0, "one datagram of two is not enough");

    let second = answer_for(MRP, "Bedroom", 49153, Ipv4Addr::new(10, 0, 0, 10));
    assert_eq!(
        state.handle(SOURCE, &second, Some(&end_condition)),
        Handled::Finished
    );
    assert_eq!(count(), 1);
}

/// A rejecting end condition keeps the scan running.
#[test]
fn a_rejecting_end_condition_does_not_stop_the_scan() {
    let mut state = state(1);
    let end_condition = |_: &Response| false;
    let datagram = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));

    assert_eq!(
        state.handle(SOURCE, &datagram, Some(&end_condition)),
        Handled::Accumulated
    );
}

/// The end condition sees the fully assembled response for the winning source.
#[test]
fn the_end_condition_receives_the_assembled_response() {
    let mut state = state(1);
    let end_condition = |response: &Response| {
        response
            .services
            .iter()
            .any(|service| service.service_type == MRP && service.port == 49152)
    };
    let datagram = answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10));

    assert_eq!(
        state.handle(SOURCE, &datagram, Some(&end_condition)),
        Handled::Finished
    );
}

/// Accepting the end condition discards every other source's partial state.
#[test]
fn a_met_end_condition_collapses_to_the_winning_source() {
    let mut state = state(1);
    state.handle(
        OTHER_SOURCE,
        &answer_for(MRP, "Bedroom", 49153, Ipv4Addr::new(10, 0, 0, 11)),
        None,
    );
    let accept_anything = |_: &Response| true;
    assert_eq!(
        state.handle(
            SOURCE,
            &answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10)),
            Some(&accept_anything),
        ),
        Handled::Finished
    );

    let responses = state.into_responses();
    assert_eq!(responses.keys().collect::<Vec<_>>(), vec![&SOURCE]);
}

/// Each source is correlated independently.
#[test]
fn sources_are_correlated_separately() {
    let mut state = state(1);
    state.handle(
        SOURCE,
        &answer_for(MRP, "Kitchen", 49152, Ipv4Addr::new(10, 0, 0, 10)),
        None,
    );
    state.handle(OTHER_SOURCE, &ptr_only(MRP, "Bedroom"), None);

    let responses = state.into_responses();
    assert_eq!(responses.len(), 2);
    assert!(!responses[&SOURCE].deep_sleep);
    assert!(responses[&OTHER_SOURCE].deep_sleep);
}

/// An undecodable datagram is dropped, but upstream's `setdefault`-first ordering still leaves the
/// source in the result with an empty response.
#[test]
fn an_undecodable_datagram_still_registers_the_source() {
    let mut state = state(1);
    assert_eq!(state.handle(SOURCE, b"\xff\xfe", None), Handled::Ignored);

    let responses = state.into_responses();
    assert_eq!(responses.len(), 1);
    assert!(responses[&SOURCE].services.is_empty());
    assert!(!responses[&SOURCE].deep_sleep);
    assert_eq!(responses[&SOURCE].model, None);
}

/// A well-formed datagram with nothing parseable in it changes nothing.
#[test]
fn a_datagram_with_no_services_is_ignored() {
    let mut state = state(1);
    let empty = DnsMessage::new(DEFAULT_QUERY_ID).pack();

    assert_eq!(state.handle(SOURCE, &empty, None), Handled::Ignored);
    assert!(state.into_responses()[&SOURCE].services.is_empty());
}

/// The model is read off `_device-info._tcp.local` and surfaces on the assembled response.
#[test]
fn the_model_surfaces_on_the_response() {
    let mut state = state(1);
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    let full_name = format!("Kitchen.{DEVICE_INFO_SERVICE}");
    message.answers.push(record(
        DEVICE_INFO_SERVICE,
        QueryType::PTR,
        RecordData::Ptr(full_name.clone()),
    ));
    let mut txt = crate::dns::TxtRecords::new();
    txt.insert("model", b"J105aAP".to_vec());
    message
        .resources
        .push(record(&full_name, QueryType::TXT, RecordData::Txt(txt)));
    message.resources.push(record(
        &full_name,
        QueryType::SRV,
        RecordData::Srv(SrvData {
            priority: 0,
            weight: 0,
            port: 1234,
            target: "Kitchen.local".to_owned(),
        }),
    ));

    state.handle(SOURCE, &message.pack(), None);
    assert_eq!(
        state.into_responses()[&SOURCE].model.as_deref(),
        Some("J105aAP")
    );
}
