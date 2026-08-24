//! Test support shared by this crate's integration tests.
//!
//! Ported from pyatv's `tests/fake_udns.py` and `tests/support/dns_utils.py`. Everything here
//! exists so the real [`pyatv_mdns::mdns::unicast`] client can be exercised end to end against a
//! responder that answers exactly the way pyatv's own test suite is validated against, with no
//! network and no real device involved.

#![allow(
    dead_code,
    reason = "each integration test binary links the whole support module but uses a subset of the fixtures"
)]

pub mod dns_utils;
pub mod fake_udns;
