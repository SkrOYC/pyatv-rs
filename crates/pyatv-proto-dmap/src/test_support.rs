//! A hermetic DMAP Apple TV, compiled into the library behind the `test-support` feature.
//!
//! Mirrors `tests/fake_device/dmap.py`. It lives in `src/` rather than in `tests/` so that *other*
//! crates can stand the same device up — the umbrella crate's `connect()` tests need one — and a
//! fixture buried in this crate's `tests/` directory is reachable only from this crate's own test
//! binaries.
//!
//! Nothing here is part of the supported API. The feature is off by default, so a normal dependant
//! never compiles it; this crate's own test binaries switch it on through a self dev-dependency.
//!
//! # Two deliberate differences from pyatv's fixture
//!
//! * **A bad session id is answered with HTTP 403, not an assertion.** `_verify_auth_parameters`
//!   (`tests/fake_device/dmap.py:310-329`) asserts, because pyatv's own client never sends a stale
//!   one in its tests. An assertion inside a spawned Rust task is an invisible panic, and 403 is
//!   what a real Apple TV returns when a session has expired — which is the whole subject of pyatv
//!   issue #2 and of `test_relogin_if_session_expired`. Answering properly is what makes that path
//!   testable at all.
//! * **`force_relogin` invalidates the current session immediately.** Upstream only changes what
//!   the *next* login will hand out, which leaves the client's existing id still valid and means
//!   its own re-login test never actually re-logs in. Here the old id stops working, so the
//!   sequence the test describes — stale session, 403, re-login, retry — really happens.
//!
//! Both are recorded in [`fake_state::FakeDmapState::protocol_errors`] where they are genuine
//! client mistakes, so a test can assert the client did nothing wrong rather than only that it
//! eventually succeeded.
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

pub mod fake_dmap;
pub mod fake_state;

pub use fake_dmap::FakeDmapDevice;
pub use fake_state::{FakeDmapState, FakeDmapUseCases, PlayingResponse};
