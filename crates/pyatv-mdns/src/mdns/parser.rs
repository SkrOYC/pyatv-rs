//! Turning wire records into [`Service`] values.
//!
//! Ports `ServiceParser`, `_first_rd` and `_get_model` from `pyatv/core/mdns.py:95-168`. See
//! `docs/research/discovery-port-spec.md` §2.3.
//!
//! Nothing here touches a socket or a clock: feed it [`DnsMessage`]s, ask for [`Service`]s. That is
//! what lets the per-protocol scan handlers be tested from fixtures.

use std::net::{IpAddr, Ipv4Addr};

use crate::dns::{DnsMessage, DnsResource, QueryType, ServiceInstanceName};
use crate::service::{DEVICE_INFO_SERVICE, Response, Service};

/// Records for one owner name, in the order they arrived.
///
/// pyatv keys a second level by `qtype` (`Dict[str, Dict[int, List[DnsResource]]]`). One flat list
/// is equivalent: `_first_rd` only ever takes element `[0]` of a type's list, and pyatv's
/// `if record not in entry[record.qtype]` dedup cannot collide across types because two records
/// with different `qtype` are never equal.
#[derive(Debug, Clone)]
struct OwnerRecords {
    qname: String,
    records: Vec<DnsResource>,
}

impl OwnerRecords {
    /// pyatv's `_first_rd` (`pyatv/core/mdns.py:102-103`): the first record of a type, or `None`.
    fn first(&self, qtype: QueryType) -> Option<&DnsResource> {
        self.records.iter().find(|record| record.qtype == qtype)
    }
}

/// Accumulates records from one or more [`DnsMessage`]s, then materialises [`Service`]s.
///
/// Two-phase by design: a device's `A`, `SRV` and `TXT` records routinely arrive spread across
/// several datagrams, and an `SRV` record's target is only resolvable once the matching `A` record
/// has been seen. [`Self::add_message`] therefore only files records away, and [`Self::parse`] does
/// the cross-referencing.
///
/// # Example
///
/// ```
/// use pyatv_mdns::dns::{DnsMessage, QueryType};
/// use pyatv_mdns::mdns::ServiceParser;
///
/// let mut parser = ServiceParser::new();
/// parser.add_message(&DnsMessage::new(0x35FF));
/// assert!(parser.parse().is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ServiceParser {
    /// Owner name to records. A `Vec` rather than a map because a scan sees a handful of names and
    /// because Python's `dict` preserves insertion order, which decides the order [`Self::parse`]
    /// returns services in — `tests/core/test_mdns.py:176-199` asserts on it.
    table: Vec<OwnerRecords>,
    /// `PTR` owner name to the instance name it points at, from `ServiceParser.ptrs`.
    ptrs: Vec<(String, String)>,
}

impl ServiceParser {
    /// An empty parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// File away every record in `message`.
    ///
    /// Only the answer and additional sections are consulted, in that order — pyatv iterates
    /// `message.answers + message.resources` and never looks at the authority section
    /// (`pyatv/core/mdns.py:118`).
    ///
    /// A `PTR` record whose owner name starts with `_` is bookkeeping for "this service type
    /// exists, and this is its instance name", and goes into a separate map. Everything else,
    /// including a `PTR` whose owner name does *not* start with `_`, is filed under its owner name.
    ///
    /// Byte-identical duplicates are dropped, which is what makes a resend loop idempotent:
    /// `tests/core/test_mdns.py:252-266` adds the same message twice and asserts one stored record.
    pub fn add_message(&mut self, message: &DnsMessage) -> &mut Self {
        for record in message.answers.iter().chain(&message.resources) {
            if record.qtype == QueryType::PTR && record.qname.starts_with('_') {
                let Some(target) = record.rd.as_ptr_name() else {
                    continue;
                };
                // A Python dict assignment overwrites; the last PTR for a type wins.
                if let Some(slot) = self
                    .ptrs
                    .iter_mut()
                    .find(|(qname, _)| *qname == record.qname)
                {
                    target.clone_into(&mut slot.1);
                } else {
                    self.ptrs.push((record.qname.clone(), target.to_owned()));
                }
                continue;
            }

            let existing = self
                .table
                .iter()
                .position(|owner| owner.qname == record.qname);
            let index = existing.unwrap_or_else(|| {
                self.table.push(OwnerRecords {
                    qname: record.qname.clone(),
                    records: Vec::new(),
                });
                self.table.len() - 1
            });
            let owner = &mut self.table[index];

            if !owner.records.contains(record) {
                owner.records.push(record.clone());
            }
        }
        self
    }

    /// Cross-reference everything filed so far into [`Service`] values.
    ///
    /// Per owner name, in arrival order:
    ///
    /// 1. Split the name with [`ServiceInstanceName::split_name`]. A name that is not a DNS-SD
    ///    service instance is skipped silently — pyatv catches the `ValueError` and `continue`s
    ///    (`pyatv/core/mdns.py:139-142`), so a stray record produces no service rather than an error.
    /// 2. Take the *first* `SRV` record; its `target` names the host, its `port` is the port.
    ///    Without an `SRV` record the port is `0`, which is the same shape a sleep proxy's
    ///    answer-with-no-detail produces, and which `pyatv/core/scan.py` uses to discard a service.
    /// 3. Take the first non-link-local `A` record filed under that target. Link-local addresses
    ///    (169.254/16) are skipped; if every candidate is link-local, or there are none, the address
    ///    is `None`. There is **no fallback to the datagram's source address** — pyatv has none, and
    ///    adding one would make a sleeping device look reachable.
    /// 4. Decode the first `TXT` record's values with `decode_value`.
    ///
    /// Then, for every `PTR` that produced no service above, synthesise a placeholder with no
    /// address, port `0` and no properties (`pyatv/core/mdns.py:163-167`). Its name is the first
    /// dot-separated label of the target, which is wrong for an instance name containing a dot —
    /// upstream does not use [`ServiceInstanceName`] on this path. Reproduced as-is: the path only
    /// fires for a PTR-only answer, which in practice means a sleep proxy, and the resulting service
    /// is discarded downstream for having port `0` anyway.
    ///
    /// # IPv4 only
    ///
    /// `AAAA` records are ignored, matching pyatv. See [`super`].
    #[must_use]
    pub fn parse(&self) -> Vec<Service> {
        // Keyed by owner name so the PTR pass below can ask "did this name already yield a
        // service?", ordered because the answer order is asserted on upstream.
        let mut results: Vec<(String, Service)> = Vec::new();

        for owner in &self.table {
            let Ok(instance_name) = ServiceInstanceName::split_name(&owner.qname) else {
                continue;
            };

            let srv = owner
                .first(QueryType::SRV)
                .and_then(|record| record.rd.as_srv());
            let address = srv.and_then(|srv| self.routable_address(&srv.target));
            let properties = owner
                .first(QueryType::TXT)
                .and_then(|record| record.rd.as_txt())
                .map(crate::dns::TxtRecords::decode_properties)
                .unwrap_or_default();

            let service = Service {
                service_type: instance_name.ptr_name(),
                // pyatv casts a `None` instance straight to `str`; an instance-less owner name
                // cannot reach here through any real response, so the empty string stands in.
                name: instance_name.instance.unwrap_or_default(),
                address,
                port: srv.map_or(0, |srv| srv.port),
                properties,
            };
            upsert(&mut results, owner.qname.clone(), service);
        }

        for (qname, target) in &self.ptrs {
            if results.iter().any(|(key, _)| key == target) {
                continue;
            }
            let placeholder = Service {
                service_type: qname.clone(),
                name: target.split('.').next().unwrap_or(target).to_owned(),
                address: None,
                port: 0,
                properties: crate::dns::Properties::new(),
            };
            upsert(&mut results, target.clone(), placeholder);
        }

        results.into_iter().map(|(_, service)| service).collect()
    }

    /// Everything parsed so far, wrapped as one host's [`Response`].
    ///
    /// `deep_sleep` is the caller's to decide: it comes from the transport, since it depends on
    /// which datagrams arrived rather than on their contents alone. [`super::unicast()`] always
    /// passes `false`, matching `pyatv/core/mdns.py:215-219`.
    #[must_use]
    pub fn response(&self, deep_sleep: bool) -> Response {
        super::to_response(self, deep_sleep)
    }

    /// Owner names currently filed, in arrival order. Exposed for tests and diagnostics.
    pub fn owner_names(&self) -> impl Iterator<Item = &str> {
        self.table.iter().map(|owner| owner.qname.as_str())
    }

    /// Records filed under `qname` with the given type, in arrival order.
    ///
    /// The counterpart of pyatv's `parser.table[name][qtype]`, which
    /// `tests/core/test_mdns.py:259-266` asserts the length of to prove duplicates are dropped.
    pub fn records(&self, qname: &str, qtype: QueryType) -> impl Iterator<Item = &DnsResource> {
        self.table
            .iter()
            .filter(move |owner| owner.qname == qname)
            .flat_map(|owner| owner.records.iter())
            .filter(move |record| record.qtype == qtype)
    }

    /// First non-link-local IPv4 address filed under `target`.
    fn routable_address(&self, target: &str) -> Option<IpAddr> {
        self.table
            .iter()
            .find(|owner| owner.qname == target)?
            .records
            .iter()
            .filter(|record| record.qtype == QueryType::A)
            .filter_map(|record| match record.rd.as_ip_addr() {
                Some(IpAddr::V4(address)) => Some(address),
                // pyatv reads `A` records only, so an `AAAA` record filed under the same name is
                // not a candidate.
                _ => None,
            })
            .find(|address: &Ipv4Addr| !address.is_link_local())
            .map(IpAddr::V4)
    }
}

/// Insert or replace by key, keeping the original position — Python `dict` assignment semantics.
fn upsert(results: &mut Vec<(String, Service)>, key: String, service: Service) {
    match results.iter_mut().find(|(existing, _)| *existing == key) {
        Some(slot) => slot.1 = service,
        None => results.push((key, service)),
    }
}

/// The `model` property of the `_device-info._tcp.local` service, if one was answered.
///
/// Ports `_get_model` (`pyatv/core/mdns.py:95-99`). The value is the **raw** TXT string; mapping it
/// onto a `DeviceModel` happens later, in the scanner layer.
#[must_use]
pub fn get_model(services: &[Service]) -> Option<String> {
    services
        .iter()
        .find(|service| service.service_type == DEVICE_INFO_SERVICE)
        .and_then(|service| service.properties.get("model"))
        .cloned()
}

/// Parse one message in isolation.
///
/// The shorthand `tests/core/test_mdns.py:38-41` uses, and what
/// [`multicast()`](super::multicast()) uses for its "is this datagram interesting" preview pass —
/// that pass deliberately runs on a throwaway parser so a rejected datagram leaves no trace in the
/// accumulated state.
#[must_use]
pub fn parse_services(message: &DnsMessage) -> Vec<Service> {
    let mut parser = ServiceParser::new();
    parser.add_message(message);
    parser.parse()
}

#[cfg(test)]
mod tests;
