//! The per-device settings document.
//!
//! A field-for-field port of `pyatv/settings.py` (the pydantic models `Settings`, `InfoSettings`,
//! `ProtocolSettings` and the five per-protocol models). Names, defaults and nesting are
//! reproduced exactly, because this is the shape that lands in `~/.pyatv.conf`: a file written
//! here must load in pyatv and vice versa.
//!
//! # Serialisation rules
//!
//! pyatv dumps the model with `model_dump(exclude_defaults=True)`
//! (`pyatv/storage/__init__.py:173`), so **a field equal to its default is not written at all**.
//! That is why a freshly discovered device is stored as nothing more than its identifiers. Every
//! `skip_serializing_if` below exists to reproduce that, and field order matches pydantic's
//! declaration order so the emitted JSON is byte-identical, not merely equivalent.
//!
//! The one field that is always written is [`InfoSettings::rp_id`]. Upstream defaults it to
//! `os.urandom(6).hex()` (`pyatv/settings.py:85`), a value that can never compare equal to a
//! freshly generated default, so `exclude_defaults` never drops it. Writing it unconditionally is
//! the same behaviour without depending on a coin flip.
//!
//! Unknown keys are ignored on load, matching every model's `extra="ignore"`; serde does that by
//! default, and no `deny_unknown_fields` may be added here.

use serde::{Deserialize, Serialize};

use crate::storage::protocols::ProtocolSettings;

/// Default value of [`InfoSettings::name`] (`pyatv/settings.py:37`).
pub const DEFAULT_NAME: &str = "pyatv";
/// Default value of [`InfoSettings::mac`] (`pyatv/settings.py:38`).
///
/// Locally administered (`02`) followed by `"pyatv"` in hex, as upstream spells out.
pub const DEFAULT_MAC: &str = "02:70:79:61:74:76";
/// Default value of [`InfoSettings::device_id`] (`pyatv/settings.py:39`).
pub const DEFAULT_DEVICE_ID: &str = "FF:70:79:61:74:76";
/// Default value of [`InfoSettings::model`] (`pyatv/settings.py:41`).
pub const DEFAULT_MODEL: &str = "iPhone10,6";
/// Default value of [`InfoSettings::os_name`] (`pyatv/settings.py:42`).
pub const DEFAULT_OS_NAME: &str = "iPhone OS";
/// Default value of [`InfoSettings::os_build`] (`pyatv/settings.py:43`).
pub const DEFAULT_OS_BUILD: &str = "18G82";
/// Default value of [`InfoSettings::os_version`] (`pyatv/settings.py:44`).
pub const DEFAULT_OS_VERSION: &str = "14.7.1";

/// Whether a value still equals the default pydantic would have excluded from the dump.
pub(crate) fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// How MRP tunnelling over `AirPlay` is handled.
///
/// Ports `pyatv/settings.py:62-72` (`MrpTunnel`). The JSON spellings are the enum *values*, not
/// the member names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MrpTunnel {
    /// Set the tunnel up when the device advertises support for it.
    #[default]
    Auto,
    /// Set the tunnel up even when the device does not advertise support.
    Force,
    /// Never set a tunnel up.
    Disable,
}

/// Who this client claims to be when it talks to a device.
///
/// Ports `pyatv/settings.py:78-104` (`InfoSettings`). Every field describes *this* controller, not
/// the remote device: `name` is the name shown on the Apple TV during pairing, `model` and the
/// `os_*` trio are what the device is told about the "iPhone" it is talking to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InfoSettings {
    /// Name this client presents to the device.
    #[serde(skip_serializing_if = "InfoSettings::is_default_name")]
    pub name: String,
    /// MAC address this client presents.
    #[serde(skip_serializing_if = "InfoSettings::is_default_mac")]
    pub mac: String,
    /// Hardware model this client claims.
    #[serde(skip_serializing_if = "InfoSettings::is_default_model")]
    pub model: String,
    /// `HomeKit` device identifier of this client.
    #[serde(skip_serializing_if = "InfoSettings::is_default_device_id")]
    pub device_id: String,
    /// Remote-pairing identifier, six random bytes as lowercase hex.
    ///
    /// Generated once and persisted; always written, see the module docs. A stored `null` is
    /// replaced with a fresh value rather than rejected, which is what the `fill_missing_rp_id`
    /// validator does upstream (`pyatv/settings.py:98-104`).
    #[serde(deserialize_with = "rp_id_or_random")]
    pub rp_id: String,
    /// Operating system name this client claims.
    #[serde(skip_serializing_if = "InfoSettings::is_default_os_name")]
    pub os_name: String,
    /// Operating system build this client claims.
    #[serde(skip_serializing_if = "InfoSettings::is_default_os_build")]
    pub os_build: String,
    /// Operating system version this client claims.
    #[serde(skip_serializing_if = "InfoSettings::is_default_os_version")]
    pub os_version: String,
}

impl InfoSettings {
    fn is_default_name(value: &str) -> bool {
        value == DEFAULT_NAME
    }
    fn is_default_mac(value: &str) -> bool {
        value == DEFAULT_MAC
    }
    fn is_default_model(value: &str) -> bool {
        value == DEFAULT_MODEL
    }
    fn is_default_device_id(value: &str) -> bool {
        value == DEFAULT_DEVICE_ID
    }
    fn is_default_os_name(value: &str) -> bool {
        value == DEFAULT_OS_NAME
    }
    fn is_default_os_build(value: &str) -> bool {
        value == DEFAULT_OS_BUILD
    }
    fn is_default_os_version(value: &str) -> bool {
        value == DEFAULT_OS_VERSION
    }
}

impl Default for InfoSettings {
    /// Reproduces `InfoSettings()` with no arguments, including the freshly random
    /// [`InfoSettings::rp_id`].
    fn default() -> Self {
        Self {
            name: DEFAULT_NAME.to_owned(),
            mac: DEFAULT_MAC.to_owned(),
            model: DEFAULT_MODEL.to_owned(),
            device_id: DEFAULT_DEVICE_ID.to_owned(),
            rp_id: random_rp_id(),
            os_name: DEFAULT_OS_NAME.to_owned(),
            os_build: DEFAULT_OS_BUILD.to_owned(),
            os_version: DEFAULT_OS_VERSION.to_owned(),
        }
    }
}

/// Six random bytes as lowercase hex, the default for [`InfoSettings::rp_id`].
///
/// `os.urandom(6).hex()` (`pyatv/settings.py:85`), which is also what the `fill_missing_rp_id`
/// validator (`pyatv/settings.py:98-104`) substitutes when a stored file has a null `rp_id`.
///
/// The identifier is not a secret — it is the pairing-time equivalent of a MAC address — so when
/// the operating system refuses entropy the clock is a good enough source. Returning an error
/// instead would make every constructor in this module fallible for no security gain.
fn random_rp_id() -> String {
    let mut bytes = [0u8; 6];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        bytes[..4].copy_from_slice(&nanos.to_le_bytes());
    }

    bytes
        .iter()
        .fold(String::with_capacity(12), |mut out, byte| {
            use std::fmt::Write as _;
            // Writing into a String cannot fail; the result is discarded rather than unwrapped.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Read an `rp_id`, substituting a fresh one for a stored `null`.
///
/// # Errors
///
/// Returns the deserialiser's error if the value is neither a string nor null.
fn rp_id_or_random<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_else(random_rp_id))
}

/// Everything persisted about one device (`pyatv/settings.py:175-179`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Who this client claims to be when talking to the device.
    pub info: InfoSettings,
    /// Credentials and per-protocol tuning.
    #[serde(skip_serializing_if = "is_default")]
    pub protocols: ProtocolSettings,
}

impl Settings {
    /// Whether any of this record's identifiers appears in `identifiers`.
    ///
    /// The membership test `AbstractStorage.get_settings` runs to decide whether a config it was
    /// handed is already known (`pyatv/storage/__init__.py:102-111`).
    #[must_use]
    pub fn matches_any(&self, identifiers: &[&str]) -> bool {
        self.protocols
            .identifiers()
            .any(|stored| identifiers.contains(&stored))
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_NAME, InfoSettings, MrpTunnel, Settings, random_rp_id};
    use crate::airplay::AirPlayVersion;
    use crate::consts::Protocol;
    use crate::storage::protocols::{AirPlaySettings, ProtocolSettings};

    #[test]
    fn random_rp_id_is_twelve_hex_characters() {
        let first = random_rp_id();
        assert_eq!(first.len(), 12);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(first.chars().all(|c| !c.is_ascii_uppercase()));
        assert_ne!(first, random_rp_id(), "rp_id must not be a constant");
    }

    #[test]
    fn defaults_match_upstream_constants() {
        let info = InfoSettings::default();
        assert_eq!(info.name, DEFAULT_NAME);
        assert_eq!(info.mac, "02:70:79:61:74:76");
        assert_eq!(info.device_id, "FF:70:79:61:74:76");
        assert_eq!(info.model, "iPhone10,6");
        assert_eq!(info.os_name, "iPhone OS");
        assert_eq!(info.os_build, "18G82");
        assert_eq!(info.os_version, "14.7.1");
    }

    /// The `exclude_defaults=True` dump: only `rp_id` survives from an untouched `info`.
    #[test]
    fn a_default_record_serialises_to_rp_id_alone() {
        let settings = Settings::default();
        let json = serde_json::to_value(&settings).expect("serialising must succeed");

        assert_eq!(
            json.as_object().map(serde_json::Map::len),
            Some(1),
            "only `info` may be present: {json}"
        );
        assert_eq!(
            json["info"].as_object().and_then(|it| it.keys().next()),
            Some(&"rp_id".to_owned())
        );
    }

    #[test]
    fn non_default_protocol_fields_are_written() {
        let mut settings = Settings::default();
        settings
            .protocols
            .set_identifier(Protocol::Companion, Some("id".to_owned()));
        settings
            .protocols
            .set_credentials(Protocol::Companion, Some("creds".to_owned()));

        let json = serde_json::to_value(&settings).expect("serialising must succeed");
        assert_eq!(
            json["protocols"]["companion"],
            serde_json::json!({"identifier": "id", "credentials": "creds"})
        );
        assert!(
            json["protocols"].get("airplay").is_none(),
            "an untouched protocol slot must not be written"
        );
    }

    #[test]
    fn enum_values_use_upstreams_spellings() {
        assert_eq!(
            serde_json::to_string(&MrpTunnel::Disable).expect("serialising must succeed"),
            "\"disable\""
        );
        assert_eq!(
            serde_json::to_string(&AirPlayVersion::V2).expect("serialising must succeed"),
            "\"2\""
        );
        assert_eq!(
            serde_json::from_str::<AirPlayVersion>("\"auto\"").expect("parsing must succeed"),
            AirPlayVersion::Auto
        );
    }

    #[test]
    fn unknown_keys_are_ignored_on_load() {
        let settings: Settings = serde_json::from_str(
            r#"{"info": {"name": "x", "unknown": 1}, "protocols": {"airplay": {"future": true}}}"#,
        )
        .expect("unknown keys must not fail the load");

        assert_eq!(settings.info.name, "x");
        assert_eq!(settings.protocols.airplay, AirPlaySettings::default());
    }

    /// A file with `"rp_id": null` gets a fresh one, as `fill_missing_rp_id` does upstream.
    #[test]
    fn a_missing_rp_id_is_regenerated() {
        let settings: Settings =
            serde_json::from_str(r#"{"info": {}}"#).expect("parsing must succeed");
        assert_eq!(settings.info.rp_id.len(), 12);
    }

    #[test]
    fn matches_any_looks_across_every_protocol() {
        let mut protocols = ProtocolSettings::default();
        protocols.set_identifier(Protocol::Raop, Some("raop-id".to_owned()));
        let settings = Settings {
            protocols,
            ..Settings::default()
        };

        assert!(settings.matches_any(&["other", "raop-id"]));
        assert!(!settings.matches_any(&["other"]));
    }
}
