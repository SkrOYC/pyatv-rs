//! The sans-io half of the responder: one service instance and the messages it produces.
//!
//! Nothing here touches a socket. [`ServiceRegistration`] describes what is being published;
//! [`ServiceRegistration::respond`], [`ServiceRegistration::announcement`] and
//! [`ServiceRegistration::goodbye`] turn that into [`DnsMessage`]s that [`super::responder`] sends.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::dns::{
    CLASS_IN, DnsMessage, DnsQuestion, DnsResource, QueryType, RecordData, SrvData,
    UNICAST_RESPONSE,
};

/// The cache-flush bit, RFC 6762 §10.2.
///
/// Set on a *unique* record in a response — one that a single responder owns outright — so
/// receivers discard whatever they had cached for that name and type. `SRV`, `TXT` and `A` are
/// unique; `PTR` is shared between every instance of a service type and must not carry it.
///
/// Numerically the same bit as [`UNICAST_RESPONSE`], which is why this crate keeps record classes
/// as raw `u16` rather than an enum: the bit means two different things depending on whether it is
/// on a question or on a resource record.
pub const CACHE_FLUSH: u16 = UNICAST_RESPONSE;

/// TTL for host-bound records (`A`, `SRV`), RFC 6762 §10: two minutes.
pub const HOST_TTL: u32 = 120;

/// TTL for service-bound records (`PTR`, `TXT`), RFC 6762 §10: seventy-five minutes.
pub const SERVICE_TTL: u32 = 4500;

/// The TTL that means "this record is going away", RFC 6762 §10.1.
pub const GOODBYE_TTL: u32 = 0;

/// Maximum TTL in a legacy-unicast response, RFC 6762 §6.7.
///
/// A resolver that queried from a port other than 5353 is not an mDNS client and will not see the
/// goodbye records, so its cache entries are capped at ten seconds instead.
pub const LEGACY_UNICAST_TTL: u32 = 10;

/// Header flags on every response: `QR` (this is a response) and `AA` (authoritative).
///
/// RFC 6762 §18.2-18.4. Every other flag must be zero in multicast DNS.
pub const RESPONSE_FLAGS: u16 = 0x8400;

/// How many unsolicited announcements to send at startup, RFC 6762 §8.3.
///
/// The RFC requires at least two and permits up to eight; three is what makes a service visible on
/// a lossy link without spamming it.
pub const ANNOUNCE_COUNT: u32 = 3;

/// Gap between announcements, RFC 6762 §8.3 ("one second apart").
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(1);

/// One service instance to publish.
///
/// The fields map one-for-one onto pyatv's `mdns.Service(type, name, address, port, properties)`
/// (`pyatv/protocols/dmap/pairing.py:300-306`), except that `addresses` is plural: pyatv publishes
/// a separate service per local address, all pointing at the same port, whereas one registration
/// here carries every address as its own `A` record under one host name. The observable result on
/// the wire is the same set of addresses reachable through one instance, with less duplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRegistration {
    /// DNS-SD service type, without a trailing dot, e.g. `_touch-remote._tcp.local`.
    pub service_type: String,
    /// Instance label. Becomes the first label of the instance name.
    ///
    /// A DNS-SD instance label may legally contain dots (RFC 6763 §4.1.1), but this responder
    /// encodes the instance name by splitting on dots, so a label containing one would be split
    /// into two. Every caller in this workspace uses a dot-free label; see the module docs on the
    /// deliberately narrow scope.
    pub instance: String,
    /// Host name the `SRV` record points at, e.g. `my-host.local`.
    pub host: String,
    /// TCP port the service listens on.
    pub port: u16,
    /// Addresses to publish as `A` records for [`Self::host`].
    pub addresses: Vec<Ipv4Addr>,
    /// TXT properties, in order, **case preserved**.
    ///
    /// Deliberately a `Vec` of pairs rather than [`crate::dns::TxtRecords`]: that map lowercases
    /// keys on insert, which is right for the *client* side (pyatv's `CaseInsensitiveDict` does the
    /// same) and wrong here. An Apple TV browsing for `_touch-remote._tcp` reads `DvNm`, `RemV`,
    /// `DvTy`, `RemN` and `Pair` with exactly that capitalisation.
    pub properties: Vec<(String, String)>,
}

impl ServiceRegistration {
    /// A registration with no addresses and no properties.
    #[must_use]
    pub fn new(
        service_type: impl Into<String>,
        instance: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            service_type: service_type.into(),
            instance: instance.into(),
            host: host.into(),
            port,
            addresses: Vec::new(),
            properties: Vec::new(),
        }
    }

    /// Add an address to publish.
    #[must_use]
    pub fn with_address(mut self, address: Ipv4Addr) -> Self {
        self.addresses.push(address);
        self
    }

    /// Add a TXT property. The key's case is preserved exactly.
    #[must_use]
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.push((key.into(), value.into()));
        self
    }

    /// The fully qualified instance name, `<instance>.<service_type>`.
    #[must_use]
    pub fn instance_name(&self) -> String {
        format!("{}.{}", self.instance, self.service_type)
    }

    /// TXT RDATA: one length-prefixed `key=value` character-string per property, RFC 6763 §6.
    ///
    /// A property whose chunk would exceed the 255-byte character-string limit is skipped rather
    /// than truncated, matching [`crate::dns::TxtRecords::encode`].
    ///
    /// An empty property list encodes as a single zero byte, not as zero bytes: RFC 6763 §6.1
    /// requires TXT RDATA to be at least one byte long, and an empty character string is how a
    /// service says "no properties".
    #[must_use]
    pub fn txt_rdata(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (key, value) in &self.properties {
            let Ok(length) = u8::try_from(key.len() + 1 + value.len()) else {
                tracing::warn!(key, "TXT entry exceeds 255 bytes, skipping");
                continue;
            };
            out.push(length);
            out.extend_from_slice(key.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value.as_bytes());
        }
        if out.is_empty() {
            out.push(0);
        }
        out
    }

    /// The `PTR` record pointing the service type at this instance.
    #[must_use]
    pub fn ptr_record(&self, ttl: u32) -> DnsResource {
        DnsResource {
            qname: self.service_type.clone(),
            qtype: QueryType::PTR,
            // Shared record: no cache-flush bit, or a second instance of the same service type
            // would evict this one.
            qclass: CLASS_IN,
            ttl,
            rd: RecordData::Ptr(self.instance_name()),
        }
    }

    /// The `SRV` record giving the instance's port and target host.
    #[must_use]
    pub fn srv_record(&self, ttl: u32) -> DnsResource {
        DnsResource {
            qname: self.instance_name(),
            qtype: QueryType::SRV,
            qclass: CLASS_IN | CACHE_FLUSH,
            ttl,
            rd: RecordData::Srv(SrvData {
                priority: 0,
                weight: 0,
                port: self.port,
                target: self.host.clone(),
            }),
        }
    }

    /// The `TXT` record carrying [`Self::properties`].
    ///
    /// The payload is [`RecordData::Other`] rather than [`RecordData::Txt`] on purpose: the latter
    /// is backed by a case-insensitive map that lowercases keys, and the wire bytes have to keep
    /// the capitalisation the browsing device expects. [`RecordData::Other`] is written verbatim.
    #[must_use]
    pub fn txt_record(&self, ttl: u32) -> DnsResource {
        DnsResource {
            qname: self.instance_name(),
            qtype: QueryType::TXT,
            qclass: CLASS_IN | CACHE_FLUSH,
            ttl,
            rd: RecordData::Other(self.txt_rdata()),
        }
    }

    /// One `A` record per published address.
    #[must_use]
    pub fn address_records(&self, ttl: u32) -> Vec<DnsResource> {
        self.addresses
            .iter()
            .map(|address| DnsResource {
                qname: self.host.clone(),
                qtype: QueryType::A,
                qclass: CLASS_IN | CACHE_FLUSH,
                ttl,
                rd: RecordData::A(*address),
            })
            .collect()
    }

    /// Every record this registration owns, in announcement order.
    #[must_use]
    pub fn all_records(&self, goodbye: bool) -> Vec<DnsResource> {
        let (host_ttl, service_ttl) = if goodbye {
            (GOODBYE_TTL, GOODBYE_TTL)
        } else {
            (HOST_TTL, SERVICE_TTL)
        };

        let mut records = vec![
            self.ptr_record(service_ttl),
            self.srv_record(host_ttl),
            self.txt_record(service_ttl),
        ];
        records.extend(self.address_records(host_ttl));
        records
    }

    /// The unsolicited announcement sent at startup, RFC 6762 §8.3.
    #[must_use]
    pub fn announcement(&self) -> DnsMessage {
        self.unsolicited(false)
    }

    /// The goodbye sent at shutdown: the same records with a zero TTL, RFC 6762 §10.1.
    #[must_use]
    pub fn goodbye(&self) -> DnsMessage {
        self.unsolicited(true)
    }

    fn unsolicited(&self, goodbye: bool) -> DnsMessage {
        DnsMessage {
            // RFC 6762 §18.1: the ID of a multicast response is zero.
            msg_id: 0,
            flags: RESPONSE_FLAGS,
            answers: self.all_records(goodbye),
            ..DnsMessage::default()
        }
    }

    /// The answer and additional records for one question, or empty if it is not ours.
    ///
    /// Follows RFC 6763 §12: a `PTR` answer carries the instance's `SRV`, `TXT` and `A` records as
    /// additionals so a browsing client needs no follow-up query, and an `SRV` answer carries the
    /// `A` records. `ANY` matches everything for the name.
    #[must_use]
    pub fn answer(&self, question: &DnsQuestion, ttl_cap: Option<u32>) -> Answer {
        let cap = |ttl: u32| ttl_cap.map_or(ttl, |cap| ttl.min(cap));
        let name = question.qname.trim_end_matches('.');
        let matches = |candidate: &str| name.eq_ignore_ascii_case(candidate);
        let wanted = |qtype: QueryType| question.qtype == qtype || question.qtype == QueryType::ANY;

        if matches(&self.service_type) && wanted(QueryType::PTR) {
            let mut additionals = vec![
                self.srv_record(cap(HOST_TTL)),
                self.txt_record(cap(SERVICE_TTL)),
            ];
            additionals.extend(self.address_records(cap(HOST_TTL)));
            return Answer {
                answers: vec![self.ptr_record(cap(SERVICE_TTL))],
                additionals,
            };
        }

        let instance = self.instance_name();
        if matches(&instance) {
            let mut answers = Vec::new();
            let mut additionals = Vec::new();
            if wanted(QueryType::SRV) {
                answers.push(self.srv_record(cap(HOST_TTL)));
                additionals.extend(self.address_records(cap(HOST_TTL)));
            }
            if wanted(QueryType::TXT) {
                answers.push(self.txt_record(cap(SERVICE_TTL)));
            }
            return Answer {
                answers,
                additionals,
            };
        }

        if matches(&self.host) && wanted(QueryType::A) {
            return Answer {
                answers: self.address_records(cap(HOST_TTL)),
                additionals: Vec::new(),
            };
        }

        Answer::default()
    }

    /// Build the response to a whole query, or `None` if nothing in it concerns this service.
    ///
    /// `legacy` selects RFC 6762 §6.7 behaviour, which the caller decides by looking at the source
    /// port: a query from anything other than port 5353 comes from a one-shot resolver rather than
    /// a full mDNS implementation, so the response echoes the query's ID, repeats the question
    /// section, and caps every TTL at [`LEGACY_UNICAST_TTL`]. A query from port 5353 gets the
    /// normal form: zero ID, no questions, full TTLs.
    #[must_use]
    pub fn respond(&self, query: &DnsMessage, legacy: bool) -> Option<DnsMessage> {
        if query.header().is_response() {
            return None;
        }

        let ttl_cap = legacy.then_some(LEGACY_UNICAST_TTL);
        let mut response = DnsMessage {
            msg_id: if legacy { query.msg_id } else { 0 },
            flags: RESPONSE_FLAGS,
            ..DnsMessage::default()
        };

        for question in &query.questions {
            let answer = self.answer(question, ttl_cap);
            if answer.is_empty() {
                continue;
            }
            if legacy {
                response.questions.push(question.clone());
            }
            extend_unique(&mut response.answers, answer.answers);
            extend_unique(&mut response.resources, answer.additionals);
        }

        if response.answers.is_empty() {
            return None;
        }

        // A record cannot be in both sections; the answer section wins.
        response
            .resources
            .retain(|record| !response.answers.contains(record));
        Some(response)
    }

    /// Whether any question in `query` that this service can answer asked for a unicast reply.
    ///
    /// The `QU` bit, RFC 6762 §5.4. Set by pyatv's own scanner on every question it sends
    /// (`create_service_queries`), so this is the common case when the peer is another pyatv.
    #[must_use]
    pub fn wants_unicast(&self, query: &DnsMessage) -> bool {
        query.questions.iter().any(|question| {
            question.wants_unicast_response() && !self.answer(question, None).is_empty()
        })
    }
}

/// What one question is answered with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer {
    /// Records that directly answer the question.
    pub answers: Vec<DnsResource>,
    /// Records a client will want next, RFC 6763 §12.
    pub additionals: Vec<DnsResource>,
}

impl Answer {
    /// Whether this question produced nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }
}

/// Append records that are not already present, so a multi-question query does not duplicate them.
fn extend_unique(target: &mut Vec<DnsResource>, records: Vec<DnsResource>) {
    for record in records {
        if !target.contains(&record) {
            target.push(record);
        }
    }
}

#[cfg(test)]
mod tests;
