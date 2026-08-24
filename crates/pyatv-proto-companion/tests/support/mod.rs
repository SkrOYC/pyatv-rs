//! Shared test scaffolding.
//!
//! Every integration test binary compiles this module separately and exercises a different slice of
//! it — the pairing tests never touch the app list, the functional tests never touch the accessory's
//! key material — so anything one binary needs looks dead to the others. Silencing that here is
//! cheaper and clearer than fragmenting the fixture per binary.
#![allow(
    dead_code,
    reason = "each test binary uses a different subset of this fixture"
)]

pub mod fake_companion;
pub mod fake_plist;
pub mod fake_state;
