//! Shared test scaffolding: a hermetic MRP device and an in-memory tunnel channel.
//!
//! Every integration test binary compiles this module separately and exercises a different slice of
//! it — the tunnel tests never pair, the pairing tests never look at now-playing state — so
//! anything one binary needs looks dead to the others. Silencing that here is cheaper and clearer
//! than fragmenting the fixture per binary.
#![allow(
    dead_code,
    reason = "each test binary uses a different subset of this fixture"
)]

pub mod fake_channels;
pub mod fake_connection;
pub mod fake_messages;
pub mod fake_mrp;
pub mod fake_state;
pub mod fake_usecases;
pub mod harness;
