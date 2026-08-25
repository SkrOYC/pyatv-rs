//! A hermetic MRP device, compiled into the library behind the `test-support` feature.
//!
//! This lives in `src/` rather than in `tests/` so that *other* crates can stand the same device
//! up. The umbrella crate's `connect()` tests run this device behind an AirPlay data-stream
//! channel, and a fixture buried in this crate's `tests/` directory is reachable only from this
//! crate's own test binaries.
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

pub mod fake_channels;
pub mod fake_connection;
pub mod fake_messages;
pub mod fake_mrp;
pub mod fake_state;
pub mod fake_usecases;
pub mod harness;
