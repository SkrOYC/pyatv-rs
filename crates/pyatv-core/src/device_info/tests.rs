//! Ports the device-info half of `tests/test_interface.py` (`tests/test_interface.py:245-386`).

use std::collections::HashMap;

use super::{DeviceInfo, DeviceInfoValue};
use crate::consts::{DeviceModel, OperatingSystem};

/// Build the map `DeviceInfo(dict)` is given upstream.
fn properties<const N: usize>(
    entries: [(&str, DeviceInfoValue); N],
) -> HashMap<String, DeviceInfoValue> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn info<const N: usize>(entries: [(&str, DeviceInfoValue); N]) -> DeviceInfo {
    DeviceInfo::from_properties(&properties(entries)).expect("valid device info")
}

/// Ports `test_device_info_various_input`, empty case.
#[test]
fn empty_properties_yield_all_unknowns() {
    let device_info = DeviceInfo::default();

    assert_eq!(device_info.operating_system(), OperatingSystem::Unknown);
    assert_eq!(device_info.version(), None);
    assert_eq!(device_info.build_number(), None);
    assert_eq!(device_info.model(), DeviceModel::Unknown);
    assert_eq!(device_info.mac(), None);
    assert_eq!(device_info.output_device_id(), None);
}

/// Ports `test_device_info_various_input`, fully-populated case.
#[test]
fn every_key_round_trips_through_the_constructor() {
    let device_info = info([
        (
            DeviceInfo::OPERATING_SYSTEM,
            DeviceInfoValue::from(OperatingSystem::TvOs),
        ),
        (DeviceInfo::VERSION, DeviceInfoValue::from("1.0")),
        (DeviceInfo::BUILD_NUMBER, DeviceInfoValue::from("ABC")),
        (DeviceInfo::MODEL, DeviceInfoValue::from(DeviceModel::Gen3)),
        (DeviceInfo::MAC, DeviceInfoValue::from("AA:BB:CC:DD:EE:FF")),
        (
            DeviceInfo::OUTPUT_DEVICE_ID,
            DeviceInfoValue::from("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
        ),
    ]);

    assert_eq!(device_info.operating_system(), OperatingSystem::TvOs);
    assert_eq!(device_info.version().as_deref(), Some("1.0"));
    assert_eq!(device_info.build_number(), Some("ABC"));
    assert_eq!(device_info.model(), DeviceModel::Gen3);
    assert_eq!(device_info.mac(), Some("AA:BB:CC:DD:EE:FF"));
    assert_eq!(
        device_info.output_device_id(),
        Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
    );
}

/// Ports `test_device_info_bad_types`: every key rejects a value of the wrong kind.
#[test]
fn wrong_value_types_are_rejected() {
    let cases = [
        (
            DeviceInfo::OPERATING_SYSTEM,
            DeviceInfoValue::from("bad"),
            "OperatingSystem",
        ),
        (
            DeviceInfo::VERSION,
            DeviceInfoValue::from(DeviceModel::Gen3),
            "String",
        ),
        (
            DeviceInfo::BUILD_NUMBER,
            DeviceInfoValue::from(DeviceModel::Gen3),
            "String",
        ),
        (
            DeviceInfo::MODEL,
            DeviceInfoValue::from("bad"),
            "DeviceModel",
        ),
        (
            DeviceInfo::MAC,
            DeviceInfoValue::from(OperatingSystem::TvOs),
            "String",
        ),
        (
            DeviceInfo::OUTPUT_DEVICE_ID,
            DeviceInfoValue::from(DeviceModel::Gen3),
            "String",
        ),
    ];

    for (field, value, expected) in cases {
        let error = DeviceInfo::from_properties(&properties([(field, value)]))
            .expect_err("wrong type must be rejected");
        assert_eq!(error.field, field);
        assert_eq!(error.expected, expected);
    }
}

/// Keys the constructor does not know are dropped, as upstream drops whatever is left unpopped.
#[test]
fn unknown_keys_are_ignored() {
    let device_info = info([("something_else", DeviceInfoValue::from("value"))]);
    assert_eq!(device_info, DeviceInfo::default());
}

/// Ports `test_device_info_guess_os`. Note `Gen2`/`Gen3` answering `TvOS`: that is upstream's
/// behaviour, and it contradicts `lookup_os_from_model`.
#[test]
fn operating_system_is_guessed_from_the_model() {
    let cases = [
        (DeviceModel::AirPortExpress, OperatingSystem::AirPortOs),
        (DeviceModel::AirPortExpressGen2, OperatingSystem::AirPortOs),
        (DeviceModel::HomePod, OperatingSystem::TvOs),
        (DeviceModel::HomePodMini, OperatingSystem::TvOs),
        (DeviceModel::Gen2, OperatingSystem::TvOs),
        (DeviceModel::Gen3, OperatingSystem::TvOs),
        (DeviceModel::Gen4, OperatingSystem::TvOs),
        (DeviceModel::Gen4K, OperatingSystem::TvOs),
        (DeviceModel::AppleTv4KGen2, OperatingSystem::TvOs),
        (DeviceModel::AppleTv4KGen3, OperatingSystem::TvOs),
    ];

    for (model, expected) in cases {
        let device_info = info([(DeviceInfo::MODEL, DeviceInfoValue::from(model))]);
        assert_eq!(device_info.operating_system(), expected, "{model:?}");
    }
}

/// The models upstream's guess has no case for, unlike `lookup_os_from_model`.
#[test]
fn operating_system_guess_has_gaps_upstream() {
    for model in [DeviceModel::HomePodGen2, DeviceModel::AppleTvGen1] {
        let device_info = info([(DeviceInfo::MODEL, DeviceInfoValue::from(model))]);
        assert_eq!(
            device_info.operating_system(),
            OperatingSystem::Unknown,
            "{model:?}"
        );
    }
}

/// An explicit operating system always wins over the guess.
#[test]
fn explicit_operating_system_wins_over_the_guess() {
    let device_info = info([
        (
            DeviceInfo::MODEL,
            DeviceInfoValue::from(DeviceModel::AirPortExpress),
        ),
        (
            DeviceInfo::OPERATING_SYSTEM,
            DeviceInfoValue::from(OperatingSystem::MacOs),
        ),
    ]);
    assert_eq!(device_info.operating_system(), OperatingSystem::MacOs);
}

/// Ports `test_device_info_resolve_version_from_build_number`.
#[test]
fn version_falls_back_to_the_build_number_table() {
    let stated = info([(DeviceInfo::VERSION, DeviceInfoValue::from("1.0"))]);
    assert_eq!(stated.version().as_deref(), Some("1.0"));

    let derived = info([(DeviceInfo::BUILD_NUMBER, DeviceInfoValue::from("18M60"))]);
    assert_eq!(derived.version().as_deref(), Some("14.7"));

    let both = info([
        (DeviceInfo::VERSION, DeviceInfoValue::from("1.0")),
        (DeviceInfo::BUILD_NUMBER, DeviceInfoValue::from("18M60")),
    ]);
    assert_eq!(both.version().as_deref(), Some("1.0"));
}

/// Ports `test_device_info_raw_model`.
#[test]
fn raw_model_is_returned_verbatim() {
    let device_info = info([(DeviceInfo::RAW_MODEL, DeviceInfoValue::from("raw"))]);
    assert_eq!(device_info.raw_model(), Some("raw"));
}

/// Ports `test_device_info_apple_tv_3_str`.
#[test]
fn display_renders_an_apple_tv_3() {
    let device_info = info([
        (
            DeviceInfo::OPERATING_SYSTEM,
            DeviceInfoValue::from(OperatingSystem::Legacy),
        ),
        (DeviceInfo::VERSION, DeviceInfoValue::from("2.2.3")),
        (DeviceInfo::BUILD_NUMBER, DeviceInfoValue::from("13D333")),
        (DeviceInfo::MODEL, DeviceInfoValue::from(DeviceModel::Gen3)),
        (DeviceInfo::MAC, DeviceInfoValue::from("aa:bb:cc:dd:ee:ff")),
    ]);

    assert_eq!(
        device_info.to_string(),
        "Apple TV 3, ATV SW 2.2.3 build 13D333"
    );
}

/// Ports `test_device_info_homepod_mini_str`.
#[test]
fn display_renders_a_homepod_mini() {
    let device_info = info([
        (
            DeviceInfo::OPERATING_SYSTEM,
            DeviceInfoValue::from(OperatingSystem::TvOs),
        ),
        (DeviceInfo::VERSION, DeviceInfoValue::from("1.2.3")),
        (DeviceInfo::BUILD_NUMBER, DeviceInfoValue::from("19A123")),
        (
            DeviceInfo::MODEL,
            DeviceInfoValue::from(DeviceModel::HomePodMini),
        ),
        (DeviceInfo::MAC, DeviceInfoValue::from("aa:bb:cc:dd:ee:ff")),
    ]);

    assert_eq!(
        device_info.to_string(),
        "HomePod Mini, tvOS 1.2.3 build 19A123"
    );
}

/// Ports `test_device_info_unknown_str`.
#[test]
fn display_renders_an_unknown_device() {
    assert_eq!(DeviceInfo::default().to_string(), "Unknown, Unknown OS");
}

/// Ports `test_device_info_raw_model_str`.
#[test]
fn display_uses_the_raw_model_when_the_model_is_unknown() {
    let device_info = info([(DeviceInfo::RAW_MODEL, DeviceInfoValue::from("raw"))]);
    assert_eq!(device_info.to_string(), "raw, Unknown OS");
}

/// Ports `test_model_str`.
#[test]
fn model_str_prefers_a_recognised_model_over_the_raw_string() {
    let unknown = info([
        (
            DeviceInfo::MODEL,
            DeviceInfoValue::from(DeviceModel::Unknown),
        ),
        (DeviceInfo::RAW_MODEL, DeviceInfoValue::from("raw")),
    ]);
    assert_eq!(unknown.model_str(), "raw");

    let known = info([
        (DeviceInfo::MODEL, DeviceInfoValue::from(DeviceModel::Gen3)),
        (DeviceInfo::RAW_MODEL, DeviceInfoValue::from("raw")),
    ]);
    assert_eq!(known.model_str(), "Apple TV 3");
}

/// The builder methods are an alternative to the map, not a different code path.
#[test]
fn builder_matches_the_map_constructor() {
    let built = DeviceInfo::default()
        .with_operating_system(OperatingSystem::TvOs)
        .with_version("17.2")
        .with_build_number("21K365")
        .with_model(DeviceModel::Gen4K)
        .with_mac("AA:BB:CC:DD:EE:FF");

    let from_map = info([
        (
            DeviceInfo::OPERATING_SYSTEM,
            DeviceInfoValue::from(OperatingSystem::TvOs),
        ),
        (DeviceInfo::VERSION, DeviceInfoValue::from("17.2")),
        (DeviceInfo::BUILD_NUMBER, DeviceInfoValue::from("21K365")),
        (DeviceInfo::MODEL, DeviceInfoValue::from(DeviceModel::Gen4K)),
        (DeviceInfo::MAC, DeviceInfoValue::from("AA:BB:CC:DD:EE:FF")),
    ]);

    assert_eq!(built, from_map);
    assert_eq!(built.to_string(), "Apple TV 4K, tvOS 17.2 build 21K365");
}
