//! Legacy DMAP/DAAP, for Apple TV generations 1 to 3.
//!
//! The oldest of the five protocols and the only one with no HAP crypto anywhere: plain HTTP/1.1 on the SRV-advertised port, DMAP binary TLV bodies, and a pairing flow where the client acts as the *server*. The spec of record is `docs/research/dmap-port-spec.md`; `docs/research/airplay-raop-dmap.md` §11 is the survey it grew out of.
//!
//! Three things about DMAP are worth knowing before reading further:
//!
//! - **The wire format is not self-describing.** A tag's four-byte key tells you nothing about how to interpret its data; you need the static tag table from pyatv's `tag_definitions.py` to know whether `cmst` is a container and `caps` an integer. [`parser`] can therefore walk the structure without the table, but cannot type the leaves without it.
//! - **Push updates are a long poll.** `playstatusupdate` with the previous response's `cmsr` revision makes the server hold the connection open until state changes. There is no event channel.
//! - **Pairing inverts the roles.** pyatv starts an HTTP server, publishes `_touch-remote._tcp.local.`, and waits for the Apple TV to call back with a PIN-derived MD5. See [`pairing`].

pub mod client;
pub mod daap;
pub mod error;
pub mod facade;
pub mod http;
pub mod pairing;
pub mod parser;
pub mod playing;
pub mod tags;

/// A hermetic DMAP device, for this crate's tests and the umbrella crate's.
#[cfg(feature = "test-support")]
pub mod test_support;

pub use client::BaseDmapAppleTV;
pub use daap::DaapRequester;
pub use error::Error;
pub use facade::{DmapSetupOptions, setup};
pub use pairing::{DmapPairingHandler, DmapPairingOptions};
pub use parser::{DmapEntry, DmapValue, first, parse};

/// Convenience alias for fallible DMAP operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
