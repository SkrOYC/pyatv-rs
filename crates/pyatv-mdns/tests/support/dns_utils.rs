//! Message builders ported from `tests/support/dns_utils.py`.

use pyatv_mdns::dns::{DnsResource, QueryType, RecordData, SrvData, TxtRecords};

/// `tests/support/dns_utils.py:10`.
pub const DEFAULT_QCLASS: u16 = 1;
/// `tests/support/dns_utils.py:11`.
pub const DEFAULT_TTL: u32 = 10;

/// A `PTR` answer pointing a service type at one instance name (`dns_utils.answer`).
#[must_use]
pub fn answer(qname: &str, full_name: &str) -> DnsResource {
    resource(qname, QueryType::PTR, RecordData::Ptr(full_name.to_owned()))
}

/// A resource record with the fixture defaults (`dns_utils.resource`).
#[must_use]
pub fn resource(qname: &str, qtype: QueryType, rd: RecordData) -> DnsResource {
    DnsResource {
        qname: qname.to_owned(),
        qtype,
        qclass: DEFAULT_QCLASS,
        ttl: DEFAULT_TTL,
        rd,
    }
}

/// A `TXT` payload from `(key, value)` pairs (`dns_utils.properties`).
#[must_use]
pub fn properties(entries: &[(&str, &[u8])]) -> RecordData {
    let mut records = TxtRecords::new();
    for (key, value) in entries {
        records.insert(key, (*value).to_vec());
    }
    RecordData::Txt(records)
}

/// An `SRV` payload with priority and weight zero, as every fixture uses.
#[must_use]
pub fn srv(port: u16, target: &str) -> RecordData {
    RecordData::Srv(SrvData {
        priority: 0,
        weight: 0,
        port,
        target: target.to_owned(),
    })
}
