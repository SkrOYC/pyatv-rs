//! Companion session bring-up: the command chain that follows a successful pair-verify.
//!
//! Port of `CompanionAPI.connect()` (`pyatv/protocols/companion/api.py:135-159`) and the five
//! commands it awaits. This deliberately sits **above** [`crate::protocol`] rather than inside it,
//! mirroring pyatv's own split — `protocol.py` is transport and envelope only, `api.py` owns the
//! command catalogue and the bring-up order (`docs/research/companion-port-spec.md` §2.4, §3.1).
//!
//! The order is a strict sequential chain, not a set of independent calls:
//!
//! ```text
//! _systemInfo -> _touchStart -> _sessionStart -> TVRCSessionStart -> _tiStart -> _interest(_iMC)
//! ```
//!
//! Only one ordering dependency is documented upstream (`tvremoted` refuses `FetchAttentionState`
//! until a TV-Remote-Client session exists, `api.py:229-232`), but this is the only sequence known
//! to work against real hardware, so the whole chain is treated as ordering-significant.
//!
//! Every numeric literal below is copied verbatim. pyatv's own comments call them "a bunch of
//! semi-random values" and guess at half the field names; changing them risks breaking devices that
//! pattern-match on the exact values, and there is nothing to be gained by inventing better ones.

use pyatv_opack::{Value, opack};

use crate::protocol::CompanionProtocol;
use crate::{Error, Result};

/// Service type every Companion session registers under (`api.py:216,245`).
pub const SERVICE_TYPE: &str = "com.apple.tvremoteservices";

/// The virtual trackpad's dimensions, in the device's own coordinate space (`api.py:88-89`).
///
/// Floats, not integers: they encode as OPACK tag `0x36`, and pyatv's own type is `float`.
pub const TOUCHPAD_WIDTH: f64 = 1000.0;
/// Trackpad height; see [`TOUCHPAD_WIDTH`].
pub const TOUCHPAD_HEIGHT: f64 = 1000.0;

/// The media-control event every client subscribes to during bring-up (`api.py:159`).
pub const MEDIA_CONTROL_EVENT: &str = "_iMC";

/// Identity this controller presents to the device in `_systemInfo`.
///
/// Field defaults are pyatv's `InfoSettings` (`pyatv/settings.py:37-44,78-88`), which is what a
/// user who never customised anything sends today.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// Display name of this controller.
    pub name: String,
    /// Model identifier this controller claims to be.
    pub model: String,
    /// Device identifier, MAC-shaped. Sent as `_pubID`, with a comment upstream conceding it is
    /// "not really device id here, but better then anything".
    pub device_id: String,
    /// Remote-pairing identifier, six random bytes as hex.
    ///
    /// Sent as the content-level `_i`, falling back to a colon-stripped lowercase `device_id`.
    /// **This field is load-bearing**: a null `_i` stops the device pushing `TVSystemStatus`
    /// power-state events at all (`api.py:200-201`), so it is never left empty.
    pub rp_id: Option<String>,
    /// The controller's pairing identifier, from the stored credentials. Sent as `_idsID`.
    pub client_id: Vec<u8>,
}

impl SystemInfo {
    /// pyatv's defaults, with a freshly generated `rp_id` and the caller's pairing identifier.
    #[must_use]
    pub fn new(client_id: Vec<u8>) -> Self {
        Self {
            name: "pyatv".to_owned(),
            model: "iPhone10,6".to_owned(),
            device_id: "FF:70:79:61:74:76".to_owned(),
            rp_id: Some(hex_identifier()),
            client_id,
        }
    }

    /// The content-level `_i`: `rp_id`, or a colon-stripped lowercase `device_id`
    /// (`api.py:198-202`).
    #[must_use]
    pub fn instance_identifier(&self) -> String {
        self.rp_id
            .clone()
            .unwrap_or_else(|| self.device_id.replace(':', "").to_ascii_lowercase())
    }

    /// The `_systemInfo` content dict, in upstream's key order.
    #[must_use]
    pub fn to_content(&self) -> Value {
        opack! {
            "_bf" => 0u64,
            "_cf" => 512u64,
            "_clFl" => 128u64,
            "_i" => self.instance_identifier(),
            "_idsID" => self.client_id.clone(),
            "_pubID" => self.device_id.as_str(),
            "_sf" => 256u64,
            "_sv" => "170.18",
            "model" => self.model.as_str(),
            "name" => self.name.as_str(),
        }
    }
}

/// Six random bytes as lowercase hex, matching `os.urandom(6).hex()` (`pyatv/settings.py:85`).
fn hex_identifier() -> String {
    use std::fmt::Write as _;

    let bytes: [u8; 6] = rand::random();
    bytes
        .iter()
        .fold(String::with_capacity(12), |mut out, byte| {
            // Writing into a `String` is infallible; the `Result` exists only for the generic trait.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// What bring-up established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// The composite 64-bit session identifier `_sessionStop` must later quote back.
    pub sid: u64,
}

/// Run the full bring-up chain on an encrypted connection.
///
/// # Errors
///
/// Returns [`Error::NotReady`] if the connection is not encrypted yet — every command below is
/// sent as `E_OPACK` and a device refuses them before pair-verify — plus anything
/// [`CompanionProtocol::send_command`] can return. `TVRCSessionStart` is the one exception: its
/// failure is swallowed, exactly as upstream's bare `except Exception` does, because older devices
/// do not implement it (`api.py:227-239`).
pub async fn begin_session(protocol: &mut CompanionProtocol, info: &SystemInfo) -> Result<Session> {
    if !protocol.is_encrypted() {
        return Err(Error::NotReady(
            "session bring-up needs an encrypted connection; run pair-verify first",
        ));
    }

    tracing::debug!("sending Companion system information");
    protocol
        .send_command("_systemInfo", info.to_content())
        .await?;

    tracing::debug!("starting the Companion touch session");
    protocol
        .send_command(
            "_touchStart",
            opack! {
                "_height" => TOUCHPAD_HEIGHT,
                "_tFl" => 0u64,
                "_width" => TOUCHPAD_WIDTH,
            },
        )
        .await?;

    let sid = start_session(protocol).await?;

    // Deliberately non-fatal: pyatv wraps this in a bare `except Exception` because devices that
    // predate the command simply refuse it, and bring-up must continue regardless.
    match protocol
        .send_command("TVRCSessionStart", opack! { "ProtocolVersionKey" => "1.2" })
        .await
    {
        Ok(_) => tracing::debug!("started the TV Remote Client session"),
        Err(error) => tracing::debug!(%error, "TVRCSessionStart not supported"),
    }

    tracing::debug!("starting the Companion text-input session");
    protocol.send_command("_tiStart", opack! {}).await?;

    // `subscribe_event` is an Event, not a Request: the device never answers it (`api.py:267-271`).
    protocol
        .send_event(
            "_interest",
            opack! { "_regEvents" => Value::array([MEDIA_CONTROL_EVENT]) },
        )
        .await?;

    Ok(Session { sid })
}

/// `_sessionStart`, and the 64-bit composite identifier it produces.
///
/// The client picks a random `u32`, the device answers with one of its own, and the session id is
/// `(remote << 32) | local` (`api.py:213-225`). Only `_sessionStop` ever uses it.
async fn start_session(protocol: &mut CompanionProtocol) -> Result<u64> {
    let local_sid: u32 = rand::random();

    let response = protocol
        .send_command(
            "_sessionStart",
            opack! {
                "_srvT" => SERVICE_TYPE,
                "_sid" => u64::from(local_sid),
            },
        )
        .await?;

    let remote_sid = response
        .content
        .get("_sid")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::Envelope("_sessionStart returned no _sid".to_owned()))?;

    let sid = (remote_sid << 32) | u64::from(local_sid);
    tracing::debug!(sid = format!("{sid:#X}"), "started the Companion session");
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::{SystemInfo, TOUCHPAD_HEIGHT, TOUCHPAD_WIDTH};
    use pyatv_opack::Value;

    fn info() -> SystemInfo {
        SystemInfo::new(b"4D797FD3-3538-427E-A47B-A32FC6CF3A6A".to_vec())
    }

    /// The whole payload, field for field, against `api.py:193-210`.
    #[test]
    fn system_info_matches_upstreams_payload() {
        let mut info = info();
        info.rp_id = Some("aabbccddeeff".to_owned());
        let content = info.to_content();

        assert_eq!(content.get("_bf").and_then(Value::as_u64), Some(0));
        assert_eq!(content.get("_cf").and_then(Value::as_u64), Some(512));
        assert_eq!(content.get("_clFl").and_then(Value::as_u64), Some(128));
        assert_eq!(
            content.get("_i").and_then(Value::as_str),
            Some("aabbccddeeff")
        );
        assert_eq!(
            content
                .get("_idsID")
                .and_then(Value::as_bytes)
                .map(|id| id.to_vec()),
            Some(b"4D797FD3-3538-427E-A47B-A32FC6CF3A6A".to_vec())
        );
        assert_eq!(
            content.get("_pubID").and_then(Value::as_str),
            Some("FF:70:79:61:74:76")
        );
        assert_eq!(content.get("_sf").and_then(Value::as_u64), Some(256));
        assert_eq!(content.get("_sv").and_then(Value::as_str), Some("170.18"));
        assert_eq!(
            content.get("model").and_then(Value::as_str),
            Some("iPhone10,6")
        );
        assert_eq!(content.get("name").and_then(Value::as_str), Some("pyatv"));
    }

    /// Key order is part of the format: OPACK's back-reference table indexes first appearances.
    #[test]
    fn system_info_keys_are_in_upstreams_order() {
        let Value::Dict(entries) = info().to_content() else {
            panic!("the payload must be a dict");
        };
        let keys: Vec<&str> = entries.iter().filter_map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "_bf", "_cf", "_clFl", "_i", "_idsID", "_pubID", "_sf", "_sv", "model", "name"
            ]
        );
    }

    /// A missing `rp_id` falls back to the colon-stripped lowercase device id rather than to an
    /// empty string, which would stop the device pushing power-state events.
    #[test]
    fn a_missing_rp_id_falls_back_to_the_device_id() {
        let mut info = info();
        info.rp_id = None;
        assert_eq!(info.instance_identifier(), "ff7079617476");
    }

    #[test]
    fn a_generated_rp_id_is_twelve_hex_characters() {
        let identifier = info().rp_id.expect("a fresh SystemInfo generates one");
        assert_eq!(identifier.len(), 12);
        assert!(
            identifier
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_ne!(identifier, info().rp_id.unwrap());
    }

    /// The trackpad dimensions are floats upstream, so they must encode as OPACK float64 rather
    /// than as small integers.
    #[test]
    fn the_touchpad_dimensions_are_floats() {
        assert_eq!(Value::from(TOUCHPAD_WIDTH), Value::Float(1000.0));
        assert_eq!(Value::from(TOUCHPAD_HEIGHT), Value::Float(1000.0));
    }
}
