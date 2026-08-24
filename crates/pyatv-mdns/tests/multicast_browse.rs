//! Manual integration test for [`pyatv_mdns::mdns::multicast`] against a real network.
//!
//! Ignored by default. A real multicast browse needs a link with a cooperating device on it, a
//! kernel that will route `224.0.0.251`, and — because the wildcard listener binds port 5353 —
//! either `SO_REUSEPORT` or no system responder in the way. CI runners routinely have none of
//! those, and a test that quietly finds nothing is worse than no test.
//!
//! The behaviour that can be tested hermetically is: query construction (unit tests in
//! `src/mdns/query.rs`), per-host correlation, deep-sleep detection and the end condition (unit
//! tests in `src/mdns/multicast/tests.rs`), and the full client/responder round trip over the
//! unicast path (`tests/unicast_scan.rs`).
//!
//! Run it by hand on a network with an Apple TV or HomePod present:
//!
//! ```text
//! cargo test -p pyatv-mdns --test multicast_browse -- --ignored --nocapture
//! ```

use std::time::Duration;

use pyatv_mdns::mdns::{MDNS_PORT, MULTICAST_GROUP, multicast};

/// Browse the real multicast group for every Apple service type and print what answers.
#[tokio::test]
#[ignore = "needs a real network with a responding device; see this file's documentation"]
async fn a_real_multicast_browse_finds_devices() {
    let services: Vec<String> = [
        "_mediaremotetv._tcp.local",
        "_companion-link._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_touch-able._tcp.local",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();

    let responses = multicast(
        &services,
        MULTICAST_GROUP,
        MDNS_PORT,
        Duration::from_secs(4),
        None,
    )
    .await
    .expect("the wildcard listener binds");

    for (host, response) in &responses {
        println!(
            "{host} (deep_sleep={}, model={:?})",
            response.deep_sleep, response.model
        );
        for service in &response.services {
            println!(
                "    {} {:?} port={} address={:?}",
                service.service_type, service.name, service.port, service.address
            );
        }
    }

    assert!(
        !responses.is_empty(),
        "no host answered; is a device awake on this link?"
    );
}
