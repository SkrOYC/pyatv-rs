//! Turning library values into the JSON `atvscript` produces.
//!
//! Two rules govern everything here, both from `output_playing._convert`
//! (`pyatv/scripts/atvscript.py:213-216`):
//!
//! ```python
//! if isinstance(field, Enum):
//!     return field.name.lower()
//! return field if field else None
//! ```
//!
//! 1. **Enums render as their member name, lowercased** — not as their display string. The two
//!    coincide for most of pyatv's enums but not all of them, which is why the mappings that
//!    differ are written out rather than derived from [`std::fmt::Display`].
//! 2. **Falsy values become `null`.** Python truthiness, so an empty string and a zero are as
//!    absent as a `None`. [`truthy_text`] and [`truthy_number`] are that rule.
//!
//! The two `device_info` fields are the exception to rule 1: `_scan_devices` reads `.name` without
//! lowercasing (`atvscript.py:245-247`), so `"Gen4K"` and `"TvOS"` appear with their original
//! casing.

use pyatv::{
    App, BaseConfig, DeviceInfo, DeviceModel, KeyboardFocusState, MediaType, OperatingSystem,
    OutputDevice, Playing, PowerState,
};
use serde_json::{Map, Value};

/// A string, or `null` when it is absent or empty.
fn truthy_text(value: Option<&str>) -> Value {
    match value {
        Some(text) if !text.is_empty() => Value::String(text.to_owned()),
        _ => Value::Null,
    }
}

/// A number, or `null` when it is absent or zero.
fn truthy_number(value: Option<impl Into<Value> + PartialEq + Default>) -> Value {
    match value {
        Some(number) if number != Default::default() => number.into(),
        _ => Value::Null,
    }
}

/// A [`PowerState`] as `power_state` (`atvscript.py:79`).
#[must_use]
pub fn power_state_name(state: PowerState) -> &'static str {
    match state {
        PowerState::Unknown => "unknown",
        PowerState::Off => "off",
        PowerState::On => "on",
    }
}

/// A [`KeyboardFocusState`] as `focus_state` (`atvscript.py:150`).
#[must_use]
pub fn focus_state_name(state: KeyboardFocusState) -> &'static str {
    match state {
        KeyboardFocusState::Unknown => "unknown",
        KeyboardFocusState::Unfocused => "unfocused",
        KeyboardFocusState::Focused => "focused",
    }
}

/// A [`DeviceModel`] as `device_info.model` — the Python member name, casing intact.
///
/// Five of these differ from the Rust variant names, which spell `TV` as `Tv` to satisfy
/// `clippy::upper_case_acronyms`: `AppleTV4KGen2`, `AppleTV4KGen3` and `AppleTVGen1`
/// (`pyatv/const.py:184,190,196`).
#[must_use]
pub fn device_model_name(model: DeviceModel) -> &'static str {
    match model {
        DeviceModel::Unknown => "Unknown",
        DeviceModel::Gen2 => "Gen2",
        DeviceModel::Gen3 => "Gen3",
        DeviceModel::Gen4 => "Gen4",
        DeviceModel::Gen4K => "Gen4K",
        DeviceModel::HomePod => "HomePod",
        DeviceModel::HomePodMini => "HomePodMini",
        DeviceModel::AirPortExpress => "AirPortExpress",
        DeviceModel::AirPortExpressGen2 => "AirPortExpressGen2",
        DeviceModel::AppleTv4KGen2 => "AppleTV4KGen2",
        DeviceModel::Music => "Music",
        DeviceModel::AppleTv4KGen3 => "AppleTV4KGen3",
        DeviceModel::HomePodGen2 => "HomePodGen2",
        DeviceModel::AppleTvGen1 => "AppleTVGen1",
    }
}

/// An [`OperatingSystem`] as `device_info.operating_system`, the Python member name
/// (`pyatv/const.py:127-147`).
#[must_use]
pub fn operating_system_name(system: OperatingSystem) -> &'static str {
    match system {
        OperatingSystem::Unknown => "Unknown",
        OperatingSystem::Legacy => "Legacy",
        OperatingSystem::TvOs => "TvOS",
        OperatingSystem::AirPortOs => "AirPortOS",
        OperatingSystem::MacOs => "MacOS",
    }
}

/// The `device_info` sub-object of a scan result (`atvscript.py:243-249`).
#[must_use]
pub fn device_info_value(info: &DeviceInfo) -> Value {
    Value::Object(Map::from_iter([
        ("mac".to_owned(), truthy_text(info.mac())),
        (
            "model".to_owned(),
            Value::String(device_model_name(info.model()).to_owned()),
        ),
        (
            "model_str".to_owned(),
            Value::String(info.model_str().to_owned()),
        ),
        (
            "operating_system".to_owned(),
            Value::String(operating_system_name(info.operating_system()).to_owned()),
        ),
        ("version".to_owned(), truthy_text(info.version().as_deref())),
    ]))
}

/// One device in the `devices` array of a `scan` result (`atvscript.py:232-252`).
#[must_use]
pub fn device_value(config: &BaseConfig) -> Value {
    let services: Vec<Value> = config
        .services
        .iter()
        .map(|service| {
            Value::Object(Map::from_iter([
                (
                    "protocol".to_owned(),
                    Value::String(service.protocol.as_str().to_ascii_lowercase()),
                ),
                ("port".to_owned(), Value::from(service.port)),
            ]))
        })
        .collect();

    let all_identifiers: Vec<Value> = config
        .all_identifiers()
        .into_iter()
        .map(|identifier| Value::String(identifier.to_owned()))
        .collect();

    Value::Object(Map::from_iter([
        ("name".to_owned(), Value::String(config.name.clone())),
        (
            "address".to_owned(),
            Value::String(config.address.to_string()),
        ),
        ("identifier".to_owned(), truthy_text(config.identifier())),
        ("all_identifiers".to_owned(), Value::Array(all_identifiers)),
        (
            "device_info".to_owned(),
            device_info_value(&config.device_info),
        ),
        ("services".to_owned(), Value::Array(services)),
    ]))
}

/// One speaker, as `outputdevices_update` reports it (`atvscript.py:108-111`).
///
/// Upstream sends `name` and `identifier` only, so the per-device `volume` the library also knows
/// is deliberately left out.
#[must_use]
pub fn output_device_value(device: &OutputDevice) -> Value {
    Value::Object(Map::from_iter([
        ("name".to_owned(), truthy_text(device.name.as_deref())),
        (
            "identifier".to_owned(),
            Value::String(device.identifier.clone()),
        ),
    ]))
}

/// Every `Playing` property, plus `app` and `app_id` (`output_playing`, `atvscript.py:210-226`).
///
/// The key set is `retrieve_commands(Playing)`, which is the sixteen names in `Playing._PROPERTIES`
/// (`pyatv/interface.py:472-489`). `app` and `app_id` are always present — `null` when no app is
/// known, never omitted (`atvscript.py:220-225`).
#[must_use]
pub fn playing_values(playing: &Playing, app: Option<&App>) -> Map<String, Value> {
    let mut values = Map::new();

    values.insert(
        "media_type".to_owned(),
        Value::String(media_type_name(playing.media_type)),
    );
    values.insert(
        "device_state".to_owned(),
        Value::String(playing.device_state.as_str().to_ascii_lowercase()),
    );
    values.insert("title".to_owned(), truthy_text(playing.title.as_deref()));
    values.insert("artist".to_owned(), truthy_text(playing.artist.as_deref()));
    values.insert("album".to_owned(), truthy_text(playing.album.as_deref()));
    values.insert("genre".to_owned(), truthy_text(playing.genre.as_deref()));
    values.insert("total_time".to_owned(), truthy_number(playing.total_time));
    values.insert("position".to_owned(), truthy_number(playing.position));
    values.insert(
        "shuffle".to_owned(),
        playing.shuffle.map_or(Value::Null, |state| {
            Value::String(state.as_str().to_ascii_lowercase())
        }),
    );
    values.insert(
        "repeat".to_owned(),
        playing.repeat.map_or(Value::Null, |state| {
            Value::String(state.as_str().to_ascii_lowercase())
        }),
    );
    values.insert("hash".to_owned(), truthy_text(playing.hash.as_deref()));
    values.insert(
        "series_name".to_owned(),
        truthy_text(playing.series_name.as_deref()),
    );
    values.insert(
        "season_number".to_owned(),
        truthy_number(playing.season_number),
    );
    values.insert(
        "episode_number".to_owned(),
        truthy_number(playing.episode_number),
    );
    values.insert(
        "content_identifier".to_owned(),
        truthy_text(playing.content_identifier.as_deref()),
    );
    values.insert(
        "itunes_store_identifier".to_owned(),
        truthy_number(playing.itunes_store_identifier),
    );

    values.insert(
        "app".to_owned(),
        truthy_text(app.map(|app| app.name.as_str())),
    );
    values.insert(
        "app_id".to_owned(),
        truthy_text(app.map(|app| app.identifier.as_str())),
    );

    values
}

/// `MediaType.TV.name.lower()` is `"tv"`, and so is `"TV".to_ascii_lowercase()` — the display
/// string and the member name happen to agree for all four variants, which this pins.
fn media_type_name(media_type: MediaType) -> String {
    media_type.as_str().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{
        device_info_value, device_model_name, focus_state_name, operating_system_name,
        output_device_value, playing_values, power_state_name,
    };
    use pyatv::{
        App, DeviceInfo, DeviceModel, DeviceState, KeyboardFocusState, MediaType, OperatingSystem,
        OutputDevice, Playing, PowerState, RepeatState, ShuffleState,
    };
    use serde_json::Value;

    /// The example response at `docs/documentation/atvscript.md:196-212`.
    #[test]
    fn playing_matches_the_documented_example() {
        let playing = Playing {
            media_type: MediaType::Music,
            device_state: DeviceState::Paused,
            title: Some("Ordinary World (Live)".to_owned()),
            artist: Some("Duran Duran".to_owned()),
            album: Some("From Mediterranea With Love - EP".to_owned()),
            genre: Some("Rock".to_owned()),
            total_time: Some(395),
            position: Some(1),
            shuffle: Some(ShuffleState::Off),
            repeat: Some(RepeatState::Off),
            hash: Some("azyFEzFpSNOSGq9ZvcaX4A".to_owned()),
            ..Playing::default()
        };
        let app = App {
            name: "Musik".to_owned(),
            identifier: "com.apple.TVMusic".to_owned(),
        };

        let values = playing_values(&playing, Some(&app));

        assert_eq!(values["media_type"], "music");
        assert_eq!(values["device_state"], "paused");
        assert_eq!(values["title"], "Ordinary World (Live)");
        assert_eq!(values["artist"], "Duran Duran");
        assert_eq!(values["album"], "From Mediterranea With Love - EP");
        assert_eq!(values["genre"], "Rock");
        assert_eq!(values["total_time"], 395);
        assert_eq!(values["position"], 1);
        assert_eq!(values["shuffle"], "off");
        assert_eq!(values["repeat"], "off");
        assert_eq!(values["hash"], "azyFEzFpSNOSGq9ZvcaX4A");
        assert_eq!(values["app"], "Musik");
        assert_eq!(values["app_id"], "com.apple.TVMusic");
    }

    /// Every one of the sixteen `Playing` properties is present even when unset, plus `app` and
    /// `app_id` (`atvscript.py:218-225`).
    #[test]
    fn every_property_is_present_on_an_idle_device() {
        let values = playing_values(&Playing::default(), None);

        for key in [
            "media_type",
            "device_state",
            "title",
            "artist",
            "album",
            "genre",
            "total_time",
            "position",
            "shuffle",
            "repeat",
            "hash",
            "series_name",
            "season_number",
            "episode_number",
            "content_identifier",
            "itunes_store_identifier",
            "app",
            "app_id",
        ] {
            assert!(values.contains_key(key), "{key} must be present");
        }
        assert_eq!(values.len(), 18, "no extra keys: {values:?}");

        assert_eq!(values["media_type"], "unknown");
        assert_eq!(values["device_state"], "idle");
        assert_eq!(values["title"], Value::Null);
        assert_eq!(values["app"], Value::Null);
        assert_eq!(values["app_id"], Value::Null);
    }

    /// `return field if field else None` — Python truthiness, so a zero and an empty string are as
    /// absent as a `None` (`atvscript.py:216`).
    #[test]
    fn falsy_values_become_null() {
        let playing = Playing {
            title: Some(String::new()),
            position: Some(0),
            total_time: Some(0),
            season_number: Some(0),
            itunes_store_identifier: Some(0),
            ..Playing::default()
        };

        let values = playing_values(&playing, None);
        assert_eq!(values["title"], Value::Null);
        assert_eq!(values["position"], Value::Null);
        assert_eq!(values["total_time"], Value::Null);
        assert_eq!(values["season_number"], Value::Null);
        assert_eq!(values["itunes_store_identifier"], Value::Null);
    }

    #[test]
    fn enum_states_use_lowercased_member_names() {
        assert_eq!(power_state_name(PowerState::On), "on");
        assert_eq!(power_state_name(PowerState::Off), "off");
        assert_eq!(power_state_name(PowerState::Unknown), "unknown");

        assert_eq!(focus_state_name(KeyboardFocusState::Focused), "focused");
        assert_eq!(focus_state_name(KeyboardFocusState::Unfocused), "unfocused");
        assert_eq!(focus_state_name(KeyboardFocusState::Unknown), "unknown");
    }

    /// The three model names whose Rust spelling differs from pyatv's.
    #[test]
    fn model_names_keep_pyatvs_capitalisation() {
        assert_eq!(
            device_model_name(DeviceModel::AppleTv4KGen2),
            "AppleTV4KGen2"
        );
        assert_eq!(
            device_model_name(DeviceModel::AppleTv4KGen3),
            "AppleTV4KGen3"
        );
        assert_eq!(device_model_name(DeviceModel::AppleTvGen1), "AppleTVGen1");
        assert_eq!(device_model_name(DeviceModel::Gen4K), "Gen4K");

        assert_eq!(operating_system_name(OperatingSystem::TvOs), "TvOS");
        assert_eq!(
            operating_system_name(OperatingSystem::AirPortOs),
            "AirPortOS"
        );
        assert_eq!(operating_system_name(OperatingSystem::MacOs), "MacOS");
    }

    /// The shape at `docs/documentation/atvscript.md:80-86`.
    #[test]
    fn device_info_matches_the_documented_example() {
        let info = DeviceInfo::default()
            .with_mac("AA:BB:CC:DD:EE:FF")
            .with_model(DeviceModel::Gen4K)
            .with_operating_system(OperatingSystem::TvOs)
            .with_version("15.5.1");

        let value = device_info_value(&info);
        assert_eq!(value["mac"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(value["model"], "Gen4K");
        assert_eq!(value["model_str"], "Apple TV 4K");
        assert_eq!(value["operating_system"], "TvOS");
        assert_eq!(value["version"], "15.5.1");
    }

    /// An unknown device: `mac` and `version` are `null`, the enums still render
    /// (`atvscript.md:134-141`).
    #[test]
    fn an_unknown_device_reports_nulls_rather_than_missing_keys() {
        let value = device_info_value(&DeviceInfo::default());
        assert_eq!(value["mac"], Value::Null);
        assert_eq!(value["version"], Value::Null);
        assert_eq!(value["model"], "Unknown");
        assert_eq!(value["model_str"], "Unknown");
        assert_eq!(value["operating_system"], "Unknown");
    }

    /// `{"name": ..., "identifier": ...}` and nothing else (`atvscript.py:108-111`).
    #[test]
    fn an_output_device_carries_name_and_identifier_only() {
        let device = OutputDevice::new("AAAA-BBBB")
            .with_name("Living room")
            .with_volume(35.0);

        let value = output_device_value(&device);
        assert_eq!(value["name"], "Living room");
        assert_eq!(value["identifier"], "AAAA-BBBB");
        assert_eq!(value.as_object().map(serde_json::Map::len), Some(2));

        let nameless = output_device_value(&OutputDevice::new("CCCC"));
        assert_eq!(nameless["name"], Value::Null);
    }
}
