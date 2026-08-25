//! A minimal mDNS *responder*: the publishing half of DNS-SD.
//!
//! Everything else in this crate is a client — it asks questions and reads answers. This module is
//! the other direction: it owns a service instance, answers `PTR`/`SRV`/`TXT`/`A` questions about
//! it, announces it unsolicited at startup, and sends goodbye records when it goes away.
//!
//! # Why it exists
//!
//! DMAP pairing inverts the usual roles. The Apple TV is the one browsing: opening "Add Remote" on
//! a gen 1-3 device makes it look for `_touch-remote._tcp.local`, and the controller has to be
//! discoverable before it can be paired with. pyatv delegates that to the third-party `zeroconf`
//! package (`pyatv/protocols/dmap/pairing.py:104-124` calls `mdns.publish`, which is
//! `Zeroconf.register_service`); there is no hand-rolled responder anywhere in pyatv, so there is
//! no upstream source to port here. See `docs/research/dmap-port-spec.md` §2.5.
//!
//! It lives in `pyatv-mdns` rather than in `pyatv-proto-dmap` for two reasons: this crate already
//! owns every byte of DNS wire format in the workspace, and a protocol crate depending on another
//! protocol crate would break the dependency direction `CLAUDE.md` fixes.
//!
//! # Scope, and what is deliberately not here
//!
//! This is not a general-purpose Zeroconf implementation and does not try to be. One registration,
//! one instance, a fixed record set, no updates after publish — which is exactly pyatv's own usage.
//! Specifically **not** implemented:
//!
//! * **Probing** (RFC 6762 §8.1). A conformant responder sends three probe queries before claiming
//!   a name and renames on conflict. The instance name DMAP publishes is derived from the local IP
//!   address (`f"{int(address):040d}"`, `pairing.py:302`), so a collision means two responders on
//!   one address — and the pairing window is seconds long. Probing would add two and a half seconds
//!   of latency to guard against a case that cannot happen.
//! * **Conflict resolution** (§9), for the same reason.
//! * **IPv6/`AAAA`**. pyatv's whole discovery path is IPv4, and so is this crate.
//!
//! What *is* implemented is the half that has to work for interop, and the rules that stop a
//! responder being a nuisance on a shared link: answering queries, including RFC 6762 §6.7
//! legacy-unicast responses (capped TTLs, no cache-flush bit) and §5.4's `QU` bit; §7.1
//! known-answer suppression; the §6 one-second-per-record multicast rate limit; and §8.3
//! announcements with §10.1 goodbyes.
//!
//! # Layout
//!
//! * [`registration`] — the sans-io half: a [`ServiceRegistration`] and the messages it produces.
//!   No sockets, no clock; every wire decision is testable from bytes alone.
//! * [`responder`] — [`Responder`], which puts that on a socket.

pub mod registration;
pub mod responder;

pub use registration::{
    ANNOUNCE_COUNT, ANNOUNCE_INTERVAL, CACHE_FLUSH, GOODBYE_TTL, HOST_TTL, LEGACY_UNICAST_TTL,
    RESPONSE_FLAGS, SERVICE_TTL, ServiceRegistration,
};
pub use responder::Responder;
