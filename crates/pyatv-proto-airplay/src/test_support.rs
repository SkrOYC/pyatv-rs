//! A hermetic AirPlay 2 receiver, compiled into the library behind the `test-support` feature.
//!
//! This lives in `src/` rather than in `tests/` so that *other* crates can stand the same receiver
//! up. The umbrella crate's `connect()` tests need an AirPlay device, a Companion device and an MRP
//! device answering at once, and a fixture buried in this crate's `tests/` directory is reachable
//! only from this crate's own test binaries.
//!
//! Nothing here is part of the supported API. The feature is off by default, so a normal dependant
//! never compiles it; this crate's own test binaries switch it on through a self dev-dependency.
#![allow(
    dead_code,
    reason = "each consumer of this fixture uses a different subset of it"
)]
#![allow(
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    reason = "a test fixture reports failure by panicking, and annotating every accessor of a \
              fixture with `#[must_use]` is noise"
)]

pub mod fake_airplay;
pub mod fake_bridge;
pub mod fake_channels;
