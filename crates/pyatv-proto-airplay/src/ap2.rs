//! AirPlay 2 remote-control session pieces: the identity a controller presents, the event-channel
//! `SETUP` body, and the reply it produces.
//!
//! Port of the parts of `AP2Session` (`pyatv/protocols/airplay/ap2_session.py`) and `InfoSettings`
//! (`pyatv/settings.py:78-96`) that the tunnel's *first* `SETUP` needs.
//! `docs/research/airplay-control-mrp-tunnel-port-spec.md` §3.4 is the byte-level reference; the
//! key set below is complete and closed, and no other key is sent in that body.
//!
//! The data-stream channel's own `SETUP` (spec §3.5) is deliberately absent: it is the next step
//! and belongs with the channel implementation that consumes its `dataPort`.

use crate::rtsp::decode_plist;
use crate::{Error, Result};

/// `sourceVersion` in every remote-control `SETUP` body — a hardcoded literal upstream, not
/// derived from [`InfoSettings`] (`ap2_session.py:123`).
pub const SOURCE_VERSION: &str = "550.10";

/// `timingProtocol` in the event-channel `SETUP` body. The remote-control tunnel carries no audio,
/// so it negotiates no timing protocol (`ap2_session.py:124`).
pub const TIMING_PROTOCOL_NONE: &str = "None";

/// The identity a controller presents to a receiver.
///
/// `InfoSettings` (`pyatv/settings.py:78-96`) with upstream's defaults (`settings.py:36-42`). Every
/// field except the per-connection `sessionUUID` is configuration, not per-session state: upstream
/// ships a *fixed* `device_id` and `mac`, so a receiver that remembers a controller by either sees
/// the same one across runs. That is reproduced rather than randomised, because diverging would
/// change how a device treats a returning controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoSettings {
    /// `name` — the label a receiver shows for this controller.
    pub name: String,
    /// `macAddress`. Upstream's default is the locally-administered `02:` prefix followed by
    /// `"pyatv"` in ASCII hex.
    pub mac: String,
    /// `deviceID`. Upstream's default is `0xFF` followed by the same `"pyatv"` bytes.
    pub device_id: String,
    /// `model` — upstream claims to be an iPhone, and so does this port.
    pub model: String,
    /// `osName`.
    pub os_name: String,
    /// `osBuildVersion`.
    pub os_build: String,
    /// `osVersion`.
    pub os_version: String,
}

impl Default for InfoSettings {
    /// pyatv's defaults verbatim (`pyatv/settings.py:36-42`).
    fn default() -> Self {
        Self {
            name: "pyatv".to_owned(),
            mac: "02:70:79:61:74:76".to_owned(),
            device_id: "FF:70:79:61:74:76".to_owned(),
            model: "iPhone10,6".to_owned(),
            os_name: "iPhone OS".to_owned(),
            os_build: "18G82".to_owned(),
            os_version: "14.7.1".to_owned(),
        }
    }
}

/// Build the event-channel `SETUP` body.
///
/// The complete key set of `AP2Session._setup_event_channel`
/// (`pyatv/protocols/airplay/ap2_session.py:119-135`). `session_uuid` is freshly drawn per
/// `setup_remote_control()` call — see [`random_uuid`] — while every other value is stable
/// configuration.
///
/// `isRemoteControlOnly: true` is what distinguishes this from an audio or screen `SETUP`: it tells
/// the receiver the session wants only the remote-control channels, no media.
#[must_use]
pub fn remote_control_setup_body(info: &InfoSettings, session_uuid: &str) -> plist::Value {
    let mut body = plist::Dictionary::new();
    body.insert("isRemoteControlOnly".to_owned(), true.into());
    body.insert("osName".to_owned(), info.os_name.as_str().into());
    body.insert("sourceVersion".to_owned(), SOURCE_VERSION.into());
    body.insert("timingProtocol".to_owned(), TIMING_PROTOCOL_NONE.into());
    body.insert("model".to_owned(), info.model.as_str().into());
    body.insert("deviceID".to_owned(), info.device_id.as_str().into());
    body.insert("osVersion".to_owned(), info.os_version.as_str().into());
    body.insert("osBuildVersion".to_owned(), info.os_build.as_str().into());
    body.insert("macAddress".to_owned(), info.mac.as_str().into());
    body.insert("sessionUUID".to_owned(), session_uuid.into());
    body.insert("name".to_owned(), info.name.as_str().into());
    plist::Value::Dictionary(body)
}

/// What the receiver answers an event-channel `SETUP` with.
///
/// Upstream reads only `eventPort` (`ap2_session.py:136`); `timingPort` is captured here because a
/// receiver sends it and knowing whether it does is part of characterising a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventChannelSetup {
    /// TCP port the *controller* dials out to for the event channel, despite the read/write key
    /// naming implying the reverse (`ap2_session.py:137-148`).
    pub event_port: u16,
    /// `timingPort`, when the receiver sends one.
    pub timing_port: Option<u16>,
}

impl EventChannelSetup {
    /// Read the ports out of a `SETUP` reply.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if the reply is not a dictionary, has no `eventPort`, or carries a
    /// port that is not a 16-bit integer.
    pub fn from_plist(value: &plist::Value) -> Result<Self> {
        let dictionary = value
            .as_dictionary()
            .ok_or_else(|| Error::Plist("SETUP reply is not a dictionary".to_owned()))?;

        Ok(Self {
            event_port: port(dictionary, "eventPort")?
                .ok_or_else(|| Error::Plist("SETUP reply has no eventPort".to_owned()))?,
            timing_port: port(dictionary, "timingPort")?,
        })
    }

    /// Read the ports out of a raw binary property list body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if `body` is not a property list or does not carry an `eventPort`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Self::from_plist(&decode_plist(body)?)
    }
}

/// Read one optional port from a `SETUP` reply.
fn port(dictionary: &plist::Dictionary, key: &str) -> Result<Option<u16>> {
    let Some(value) = dictionary.get(key) else {
        return Ok(None);
    };
    let raw = value
        .as_unsigned_integer()
        .ok_or_else(|| Error::Plist(format!("{key} is not an unsigned integer")))?;

    u16::try_from(raw)
        .map(Some)
        .map_err(|_| Error::Plist(format!("{key} {raw} is not a TCP port")))
}

/// Render bytes as uppercase hex, the casing `str(uuid4()).upper()` produces.
fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            // Writing into a `String` is infallible; the `Result` exists only for the trait.
            let _ = write!(out, "{byte:02X}");
            out
        })
}

/// A fresh uppercase RFC 4122 version-4 UUID string.
///
/// `str(uuid4()).upper()` (`ap2_session.py:130,155,157`). Upstream draws these from Python's
/// `uuid4`, which is CSPRNG-backed; the values are per-session identifiers with no secrecy
/// requirement, but drawing them from the system CSPRNG costs nothing.
#[must_use]
pub fn random_uuid() -> String {
    let mut bytes: [u8; 16] = rand::random();

    // Version 4 in the high nibble of octet 6, RFC 4122 variant in the two high bits of octet 8.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    let hex = hex_upper(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::{EventChannelSetup, InfoSettings, random_uuid, remote_control_setup_body};
    use crate::rtsp::{decode_plist, encode_plist};

    /// `pyatv/settings.py:36-42`, verbatim. A device that allowlists by `deviceID` or `macAddress`
    /// would treat a different value as a different controller.
    #[test]
    fn info_settings_default_to_pyatvs_constants() {
        let info = InfoSettings::default();

        assert_eq!(info.name, "pyatv");
        assert_eq!(info.mac, "02:70:79:61:74:76");
        assert_eq!(info.device_id, "FF:70:79:61:74:76");
        assert_eq!(info.model, "iPhone10,6");
        assert_eq!(info.os_name, "iPhone OS");
        assert_eq!(info.os_build, "18G82");
        assert_eq!(info.os_version, "14.7.1");
    }

    /// The key set is closed: eleven keys, no more and no fewer (`ap2_session.py:119-135`).
    #[test]
    fn the_setup_body_carries_exactly_pyatvs_eleven_keys() {
        let body = remote_control_setup_body(&InfoSettings::default(), "A-B-C");
        let dictionary = body.as_dictionary().expect("a dictionary");

        let mut keys: Vec<&str> = dictionary.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            [
                "deviceID",
                "isRemoteControlOnly",
                "macAddress",
                "model",
                "name",
                "osBuildVersion",
                "osName",
                "osVersion",
                "sessionUUID",
                "sourceVersion",
                "timingProtocol",
            ]
        );
    }

    /// `sourceVersion` and `timingProtocol` are literals, not [`InfoSettings`] fields, and
    /// `isRemoteControlOnly` is a real boolean rather than the integer `1`.
    #[test]
    fn the_setup_body_carries_the_hardcoded_literals() {
        let body = remote_control_setup_body(&InfoSettings::default(), "A-B-C");
        let dictionary = body.as_dictionary().expect("a dictionary");

        assert_eq!(dictionary["sourceVersion"].as_string(), Some("550.10"));
        assert_eq!(dictionary["timingProtocol"].as_string(), Some("None"));
        assert_eq!(dictionary["isRemoteControlOnly"].as_boolean(), Some(true));
        assert_eq!(dictionary["sessionUUID"].as_string(), Some("A-B-C"));
    }

    /// The body has to survive the binary plist encoder the wire uses.
    #[test]
    fn the_setup_body_round_trips_through_a_binary_plist() {
        let body = remote_control_setup_body(&InfoSettings::default(), &random_uuid());
        let encoded = encode_plist(&body).expect("encodes");

        assert!(encoded.starts_with(b"bplist00"));
        assert_eq!(decode_plist(&encoded).expect("decodes"), body);
    }

    #[test]
    fn a_setup_reply_yields_both_ports() {
        let mut reply = plist::Dictionary::new();
        reply.insert("eventPort".to_owned(), 49_153u64.into());
        reply.insert("timingPort".to_owned(), 0u64.into());
        let encoded = encode_plist(&plist::Value::Dictionary(reply)).expect("encodes");

        assert_eq!(
            EventChannelSetup::parse(&encoded).expect("parses"),
            EventChannelSetup {
                event_port: 49_153,
                timing_port: Some(0),
            }
        );
    }

    /// `timingPort` is optional; `eventPort` is not.
    #[test]
    fn a_setup_reply_without_an_event_port_is_an_error() {
        let encoded =
            encode_plist(&plist::Value::Dictionary(plist::Dictionary::new())).expect("encodes");

        assert!(EventChannelSetup::parse(&encoded).is_err());
    }

    #[test]
    fn a_setup_reply_without_a_timing_port_still_parses() {
        let mut reply = plist::Dictionary::new();
        reply.insert("eventPort".to_owned(), 7_001u64.into());
        let encoded = encode_plist(&plist::Value::Dictionary(reply)).expect("encodes");

        assert_eq!(
            EventChannelSetup::parse(&encoded)
                .expect("parses")
                .timing_port,
            None
        );
    }

    /// `str(uuid4()).upper()`: 8-4-4-4-12 uppercase hex, version 4, RFC 4122 variant.
    #[test]
    fn uuids_have_the_shape_python_renders() {
        let uuid = random_uuid();
        let groups: Vec<&str> = uuid.split('-').collect();

        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(
            uuid.chars()
                .all(|c| c == '-' || c.is_ascii_digit() || c.is_ascii_uppercase()),
            "{uuid} is not uppercase hex"
        );
        assert_eq!(groups[2].as_bytes()[0], b'4', "version nibble");
        assert!(
            matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'A' | b'B'),
            "variant nibble in {uuid}"
        );
    }

    #[test]
    fn uuids_are_not_repeated() {
        assert_ne!(random_uuid(), random_uuid());
    }
}
