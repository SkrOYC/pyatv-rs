//! Known-answer tests for the scan layer, ported from pyatv's own suite.
//!
//! Every test names the upstream test it comes from. The three sources are
//! `tests/protocols/{mrp,companion,airplay,raop,dmap}/test_*_scan.py` (per-protocol round trips),
//! `tests/test_scan_functional.py` (cross-cutting behaviour) and `tests/core/test_scan.py` (the
//! multi-service "Ohana" device). All of them go through [`super::build_configs`] with fixtures
//! built from `tests/fake_udns.py`, so they exercise the real grouping and merge rules with no
//! socket involved.

pub(crate) mod fixtures;

mod functional;
mod protocols;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use pyatv_core::{BaseConfig, Protocol};

use super::build_configs;
use crate::browse::ScanOptions;
use crate::service::Response;

/// Run a scan with no filters, the equivalent of `await multicast_scan()`.
pub(super) fn scan(responses: &HashMap<IpAddr, Response>) -> Vec<BaseConfig> {
    build_configs(responses, &ScanOptions::default())
}

/// `await multicast_scan(protocol=...)`.
pub(super) fn scan_protocols(
    responses: &HashMap<IpAddr, Response>,
    protocols: &[Protocol],
) -> Vec<BaseConfig> {
    build_configs(
        responses,
        &ScanOptions {
            protocols: protocols.iter().copied().collect(),
            ..ScanOptions::default()
        },
    )
}

/// `await multicast_scan(identifier=...)`.
pub(super) fn scan_identifiers(
    responses: &HashMap<IpAddr, Response>,
    identifiers: &[&str],
) -> Vec<BaseConfig> {
    build_configs(
        responses,
        &ScanOptions {
            identifiers: identifiers
                .iter()
                .map(|it| (*it).to_owned())
                .collect::<HashSet<_>>(),
            ..ScanOptions::default()
        },
    )
}

/// `tests/utils.py:146-152` (`assert_device`).
#[track_caller]
pub(super) fn assert_device(
    config: &BaseConfig,
    name: &str,
    address: IpAddr,
    identifier: &str,
    protocol: Protocol,
    port: u16,
    credentials: Option<&str>,
) {
    assert_eq!(config.name, name, "name");
    assert_eq!(config.address, address, "address");
    assert_eq!(config.identifier(), Some(identifier), "identifier");
    let service = config
        .get_service(protocol)
        .unwrap_or_else(|| panic!("expected a {protocol:?} service"));
    assert_eq!(service.port, port, "port");
    assert_eq!(service.credentials.as_deref(), credentials, "credentials");
}
