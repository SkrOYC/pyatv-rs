//! Known-answer tests ported from `tests/core/test_mdns.py`, split across two child modules.
//!
//! The fixture builder below mirrors `tests/support/dns_utils.py`'s `add_service`, including its
//! constants (`DEFAULT_QCLASS = 1`, `DEFAULT_TTL = 10`) and its exact field wiring: the `SRV`
//! target is always `"{name}.local"`, the `PTR` answer is only added when a service type is given,
//! and an empty property map emits no `TXT` record at all rather than an empty one.

use std::net::IpAddr;

use super::{ServiceParser, parse_services};
use crate::dns::{
    DEFAULT_QUERY_ID, DnsMessage, DnsResource, QueryType, RecordData, SrvData, TxtRecords,
};
use crate::service::Service;

/// `tests/support/dns_utils.py:10`.
const DEFAULT_QCLASS: u16 = 1;
/// `tests/support/dns_utils.py:11`.
const DEFAULT_TTL: u32 = 10;

fn resource(qname: &str, rd: RecordData) -> DnsResource {
    DnsResource {
        qname: qname.to_owned(),
        qtype: match rd {
            RecordData::A(_) => QueryType::A,
            RecordData::Aaaa(_) => QueryType::AAAA,
            RecordData::Ptr(_) => QueryType::PTR,
            RecordData::Txt(_) => QueryType::TXT,
            RecordData::Srv(_) => QueryType::SRV,
            RecordData::Other(_) => QueryType::ANY,
        },
        qclass: DEFAULT_QCLASS,
        ttl: DEFAULT_TTL,
        rd,
    }
}

fn txt(properties: &[(&str, &str)]) -> RecordData {
    let mut records = TxtRecords::new();
    for (key, value) in properties {
        records.insert(key, (*value).to_owned().into_bytes());
    }
    RecordData::Txt(records)
}

/// Port of `dns_utils.add_service`.
fn add_service(
    message: &mut DnsMessage,
    service_type: Option<&str>,
    service_name: Option<&str>,
    addresses: &[&str],
    port: u16,
    properties: &[(&str, &str)],
) {
    let Some(service_name) = service_name else {
        return;
    };

    for address in addresses {
        message.resources.push(resource(
            &format!("{service_name}.local"),
            RecordData::A(address.parse().expect("fixture address parses")),
        ));
    }

    let Some(service_type) = service_type else {
        return;
    };
    let full_name = format!("{service_name}.{service_type}");

    message
        .answers
        .push(resource(service_type, RecordData::Ptr(full_name.clone())));
    message.resources.push(resource(
        &full_name,
        RecordData::Srv(SrvData {
            priority: 0,
            weight: 0,
            port,
            target: format!("{service_name}.local"),
        }),
    ));
    if !properties.is_empty() {
        message
            .resources
            .push(resource(&full_name, txt(properties)));
    }
}

fn message_with(
    service_type: Option<&str>,
    service_name: Option<&str>,
    addresses: &[&str],
    port: u16,
    properties: &[(&str, &str)],
) -> DnsMessage {
    let mut message = DnsMessage::new(DEFAULT_QUERY_ID);
    add_service(
        &mut message,
        service_type,
        service_name,
        addresses,
        port,
        properties,
    );
    message
}

/// Port of `dns_utils.assert_service`: the first address, if any, is the expected one.
fn assert_service(
    service: &Service,
    service_type: &str,
    service_name: &str,
    addresses: &[&str],
    port: u16,
    properties: &[(&str, &str)],
) {
    assert_eq!(service.service_type, service_type);
    assert_eq!(service.name, service_name);
    assert_eq!(
        service.address,
        addresses
            .first()
            .map(|address| address.parse::<IpAddr>().expect("fixture address parses"))
    );
    assert_eq!(service.port, port);
    assert_eq!(service.properties.len(), properties.len());
    for (key, value) in properties {
        assert_eq!(
            service.properties.get(key).map(String::as_str),
            Some(*value)
        );
    }
}

mod placeholders;
mod services;
