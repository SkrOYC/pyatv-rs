//! Unit tests for [`BaseConfig`] and its `display`/`apply` submodules, split out of `mod.rs` for
//! module-size discipline.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::BaseConfig;
use crate::consts::Protocol;
use crate::models::service::BaseService;

fn config() -> BaseConfig {
    BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
}

fn service(protocol: Protocol, port: u16, identifier: Option<&str>) -> BaseService {
    let mut service = BaseService::new(protocol, port);
    service.identifier = identifier.map(ToOwned::to_owned);
    service
}

#[test]
fn new_starts_empty_and_not_ready() {
    let config = config();
    assert!(config.services.is_empty());
    assert!(!config.ready());
    assert!(config.identifier().is_none());
    assert!(config.main_service().is_none());
}

#[test]
fn add_service_merges_a_second_sighting_of_the_same_protocol() {
    let mut config = config();
    config.add_service(service(Protocol::AirPlay, 7000, Some("aa")));

    let mut second = service(Protocol::AirPlay, 8000, Some("bb"));
    second.credentials = Some("creds".to_owned());
    second
        .properties
        .insert("model".into(), "AppleTV6,2".into());
    config.add_service(second);

    assert_eq!(config.services.len(), 1);
    let merged = config.get_service(Protocol::AirPlay).expect("service");
    // merge() only carries credentials/password/properties across.
    assert_eq!(merged.credentials.as_deref(), Some("creds"));
    assert_eq!(
        merged.properties.get("model").map(String::as_str),
        Some("AppleTV6,2")
    );
    assert_eq!(merged.identifier.as_deref(), Some("aa"));
    assert_eq!(merged.port, 7000);
}

#[test]
fn add_service_appends_a_new_protocol_in_discovery_order() {
    let mut config = config();
    config.add_service(service(Protocol::Raop, 7000, Some("raop")));
    config.add_service(service(Protocol::Mrp, 49152, Some("mrp")));

    assert_eq!(
        config
            .services
            .iter()
            .map(|it| it.protocol)
            .collect::<Vec<_>>(),
        vec![Protocol::Raop, Protocol::Mrp]
    );
}

/// MRP outranks everything, regardless of the order services were discovered in.
#[test]
fn identifier_follows_the_upstream_priority_not_discovery_order() {
    let mut config = config();
    config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));
    config.add_service(service(Protocol::AirPlay, 7000, Some("airplay-id")));
    config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

    assert_eq!(config.identifier(), Some("mrp-id"));
}

#[test]
fn identifier_skips_services_without_one() {
    let mut config = config();
    config.add_service(service(Protocol::Mrp, 49152, None));
    config.add_service(service(Protocol::Dmap, 3689, Some("dmap-id")));

    assert_eq!(config.identifier(), Some("dmap-id"));
}

/// Companion is last in the identifier order but is still consulted.
#[test]
fn identifier_falls_back_to_companion() {
    let mut config = config();
    config.add_service(service(Protocol::Companion, 49153, Some("companion-id")));
    assert_eq!(config.identifier(), Some("companion-id"));
}

#[test]
fn all_identifiers_keeps_discovery_order_and_drops_empty_ones() {
    let mut config = config();
    config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));
    config.add_service(service(Protocol::Companion, 49153, None));
    config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

    assert_eq!(config.all_identifiers(), vec!["raop-id", "mrp-id"]);
}

#[test]
fn ready_needs_one_identifier() {
    let mut config = config();
    config.add_service(service(Protocol::Companion, 49153, None));
    assert!(!config.ready());
    config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));
    assert!(config.ready());
}

#[test]
fn main_service_prefers_mrp_then_dmap_then_airplay_then_raop() {
    let mut config = config();
    config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));
    assert_eq!(
        config.main_service().map(|it| it.protocol),
        Some(Protocol::Raop)
    );

    config.add_service(service(Protocol::AirPlay, 7000, Some("airplay-id")));
    assert_eq!(
        config.main_service().map(|it| it.protocol),
        Some(Protocol::AirPlay)
    );

    config.add_service(service(Protocol::Dmap, 3689, Some("dmap-id")));
    assert_eq!(
        config.main_service().map(|it| it.protocol),
        Some(Protocol::Dmap)
    );

    config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));
    assert_eq!(
        config.main_service().map(|it| it.protocol),
        Some(Protocol::Mrp)
    );
}

/// Companion cannot drive a session, so it is absent from upstream's `main_service` list.
#[test]
fn main_service_ignores_companion_only_devices() {
    let mut config = config();
    config.add_service(service(Protocol::Companion, 49153, Some("companion-id")));
    assert!(config.main_service().is_none());
}

/// Upstream's `main_service` has no `enabled` check; `connect()` filters separately.
#[test]
fn main_service_does_not_filter_disabled_services() {
    let mut config = config();
    let mut mrp = service(Protocol::Mrp, 49152, Some("mrp-id"));
    mrp.enabled = false;
    config.add_service(mrp);

    assert_eq!(
        config.main_service().map(|it| it.protocol),
        Some(Protocol::Mrp)
    );
    assert_eq!(config.enabled_services().count(), 0);
}

/// The map RAOP and DMAP index at connect time, keyed by the dotless service type.
#[test]
fn properties_are_keyed_by_service_type_and_read_case_insensitively() {
    let config = config().with_properties(HashMap::from([(
        "_airplay._tcp.local".to_owned(),
        HashMap::from([("deviceid".to_owned(), "AA:BB:CC:DD:EE:FF".to_owned())]),
    )]));

    assert!(config.has_properties("_airplay._tcp.local"));
    assert!(!config.has_properties("_raop._tcp.local"));
    // The trailing-dot spelling is a different key, as it is upstream.
    assert!(!config.has_properties("_airplay._tcp.local."));

    assert_eq!(
        config
            .properties("_airplay._tcp.local")
            .and_then(|it| it.get("deviceid"))
            .map(String::as_str),
        Some("AA:BB:CC:DD:EE:FF")
    );
    assert_eq!(
        config.property("_airplay._tcp.local", "DeviceID"),
        Some("AA:BB:CC:DD:EE:FF")
    );
    assert_eq!(config.property("_airplay._tcp.local", "missing"), None);
    assert_eq!(config.property("_raop._tcp.local", "deviceid"), None);
    assert_eq!(config.all_properties().len(), 1);
}

#[test]
fn properties_default_to_empty() {
    let config = config();
    assert!(config.all_properties().is_empty());
    assert!(config.properties("_airplay._tcp.local").is_none());
}

#[test]
fn set_credentials_reports_whether_the_protocol_exists() {
    let mut config = config();
    config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

    assert!(config.set_credentials(Protocol::Mrp, "abc"));
    assert!(!config.set_credentials(Protocol::Dmap, "abc"));
    assert_eq!(
        config
            .get_service(Protocol::Mrp)
            .and_then(|it| it.credentials.as_deref()),
        Some("abc")
    );
}

#[test]
fn display_matches_pyatv_base_config_str() {
    let mut config = config();
    config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

    let expected = [
        "       Name: Living Room",
        "   Model/SW: Unknown, Unknown OS",
        "    Address: 10.0.0.5",
        "        MAC: None",
        " Deep Sleep: False",
        "Identifiers:",
        " - mrp-id",
        "Services:",
        " - Protocol: MRP, Port: 49152, Credentials: None, Requires Password: False, \
         Password: None, Pairing: Unsupported",
    ]
    .join("\n");

    assert_eq!(config.to_string(), expected);
}

/// An empty device still renders both headings, each followed by the blank line upstream's
/// `"\n".join([])` leaves behind.
#[test]
fn display_keeps_the_blank_lines_of_an_empty_config() {
    let expected = [
        "       Name: Living Room",
        "   Model/SW: Unknown, Unknown OS",
        "    Address: 10.0.0.5",
        "        MAC: None",
        " Deep Sleep: False",
        "Identifiers:",
        "",
        "Services:",
        "",
    ]
    .join("\n");

    assert_eq!(config().to_string(), expected);
}

#[test]
fn apply_puts_each_protocols_settings_on_its_own_service() {
    let mut config = config();
    config.add_service(service(Protocol::Companion, 49153, Some("companion-id")));
    config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));

    let mut settings = crate::storage::Settings::default();
    settings
        .protocols
        .set_credentials(Protocol::Companion, Some("companion-creds".to_owned()));
    settings
        .protocols
        .set_credentials(Protocol::Raop, Some("raop-creds".to_owned()));
    settings
        .protocols
        .set_password(Protocol::Raop, Some("hunter2".to_owned()));
    // A protocol the device does not advertise must not invent a service.
    settings
        .protocols
        .set_credentials(Protocol::Mrp, Some("mrp-creds".to_owned()));

    config.apply(&settings);

    let companion = config.get_service(Protocol::Companion).expect("service");
    assert_eq!(companion.credentials.as_deref(), Some("companion-creds"));
    assert_eq!(companion.password, None);

    let raop = config.get_service(Protocol::Raop).expect("service");
    assert_eq!(raop.credentials.as_deref(), Some("raop-creds"));
    assert_eq!(raop.password.as_deref(), Some("hunter2"));

    assert!(config.get_service(Protocol::Mrp).is_none());
}

#[test]
fn apply_never_clears_a_value_the_config_already_has() {
    let mut config = config();
    let mut companion = service(Protocol::Companion, 49153, Some("companion-id"));
    companion.credentials = Some("from-the-command-line".to_owned());
    config.add_service(companion);

    config.apply(&crate::storage::Settings::default());

    assert_eq!(
        config
            .get_service(Protocol::Companion)
            .and_then(|it| it.credentials.as_deref()),
        Some("from-the-command-line")
    );
}
