//! The five per-protocol settings slots.
//!
//! Ports `pyatv/settings.py:107-172`: `AirPlaySettings`, `CompanionSettings`, `DmapSettings`,
//! `MrpSettings`, `RaopSettings` and the [`ProtocolSettings`] container that holds one of each.
//! The set of fields differs per protocol and the differences are load-bearing — Companion, DMAP
//! and MRP have no `password`, and only RAOP carries the transport tuning — so the five are five
//! distinct types rather than one shared struct. Adding a field pyatv's model does not have would
//! write a key pyatv silently drops on its next save.
//!
//! The `skip_serializing_if` rules reproduce `model_dump(exclude_defaults=True)`; see
//! [`super::settings`] for the full explanation.

use serde::{Deserialize, Serialize};

use crate::airplay::AirPlayVersion;
use crate::consts::Protocol;
use crate::storage::settings::{MrpTunnel, is_default};

/// Settings for the `AirPlay` protocol (`pyatv/settings.py:107-114`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AirPlaySettings {
    /// Identifier the device advertises for this protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Credentials from a previous pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// Password, for receivers that demand one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Whether MRP may be tunnelled over this `AirPlay` connection.
    #[serde(skip_serializing_if = "is_default")]
    pub mrp_tunnel: MrpTunnel,
}

/// Settings for the Companion protocol (`pyatv/settings.py:117-121`).
///
/// Note the absence of `password`: Companion has no password concept upstream, and adding one here
/// would write a key pyatv's model discards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CompanionSettings {
    /// Identifier the device advertises for this protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Credentials from a previous pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

/// Settings for the legacy DMAP protocol (`pyatv/settings.py:124-128`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmapSettings {
    /// Identifier the device advertises for this protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Credentials from a previous pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

/// Settings for the MRP protocol (`pyatv/settings.py:131-135`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MrpSettings {
    /// Identifier the device advertises for this protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Credentials from a previous pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

/// Settings for the RAOP protocol (`pyatv/settings.py:138-162`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RaopSettings {
    /// Identifier the device advertises for this protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Credentials from a previous pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// Password, for receivers that demand one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Which `AirPlay` version to speak; `Auto` reads it off the advertised feature bits.
    #[serde(skip_serializing_if = "is_default")]
    pub protocol_version: AirPlayVersion,
    /// Local UDP port for the timing server, or `0` to pick a free one.
    ///
    /// A `u32` rather than a `u16` because the file this comes from is written by pyatv too, and
    /// pyatv's field is a plain pydantic `int` with no bound (`settings.py:152-162`). Deserialising
    /// into a `u16` made an out-of-range value fail the **whole file**: one nonsense port and every
    /// stored credential for every device became unreadable. Validation belongs at the point of use
    /// — see [`RaopSettings::timing`] — where the blast radius is one setting.
    #[serde(skip_serializing_if = "is_default")]
    pub timing_port: u32,
    /// Local UDP port for the control server, or `0` to pick a free one.
    ///
    /// See [`RaopSettings::timing_port`] for why this is a `u32`.
    #[serde(skip_serializing_if = "is_default")]
    pub control_port: u32,
}

impl RaopSettings {
    /// The timing-server port, or `None` if the stored value is not a usable one.
    ///
    /// `0` is `None` too: pyatv's own docstring says "Set to 0 to use random free port", so zero
    /// and "out of range" both mean "pick one for me".
    #[must_use]
    pub fn timing(&self) -> Option<u16> {
        port(self.timing_port, "timing_port")
    }

    /// The control-server port, or `None` if the stored value is not a usable one.
    #[must_use]
    pub fn control(&self) -> Option<u16> {
        port(self.control_port, "control_port")
    }
}

/// Narrow a stored port to a real one, complaining rather than failing if it is not.
fn port(value: u32, field: &'static str) -> Option<u16> {
    match u16::try_from(value) {
        Ok(0) => None,
        Ok(port) => Some(port),
        Err(_) => {
            tracing::warn!(
                field,
                value,
                "stored port is out of range; picking a free one"
            );
            None
        }
    }
}

/// The five per-protocol slots (`pyatv/settings.py:165-172`).
///
/// Field order matters: it is the order the keys appear in `~/.pyatv.conf`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolSettings {
    /// `AirPlay` slot.
    #[serde(skip_serializing_if = "is_default")]
    pub airplay: AirPlaySettings,
    /// Companion slot.
    #[serde(skip_serializing_if = "is_default")]
    pub companion: CompanionSettings,
    /// DMAP slot.
    #[serde(skip_serializing_if = "is_default")]
    pub dmap: DmapSettings,
    /// MRP slot.
    #[serde(skip_serializing_if = "is_default")]
    pub mrp: MrpSettings,
    /// RAOP slot.
    #[serde(skip_serializing_if = "is_default")]
    pub raop: RaopSettings,
}

impl ProtocolSettings {
    /// The identifier stored for one protocol.
    #[must_use]
    pub fn identifier(&self, protocol: Protocol) -> Option<&str> {
        match protocol {
            Protocol::AirPlay => self.airplay.identifier.as_deref(),
            Protocol::Companion => self.companion.identifier.as_deref(),
            Protocol::Dmap => self.dmap.identifier.as_deref(),
            Protocol::Mrp => self.mrp.identifier.as_deref(),
            Protocol::Raop => self.raop.identifier.as_deref(),
        }
    }

    /// Replace the identifier stored for one protocol.
    ///
    /// Assigning `None` clears it, exactly as `settings.protocols.<p>.identifier =
    /// service.identifier` does upstream (`pyatv/storage/__init__.py:146`) — that assignment is
    /// unconditional there, unlike the credentials update next to it.
    pub fn set_identifier(&mut self, protocol: Protocol, identifier: Option<String>) {
        match protocol {
            Protocol::AirPlay => self.airplay.identifier = identifier,
            Protocol::Companion => self.companion.identifier = identifier,
            Protocol::Dmap => self.dmap.identifier = identifier,
            Protocol::Mrp => self.mrp.identifier = identifier,
            Protocol::Raop => self.raop.identifier = identifier,
        }
    }

    /// Every identifier this device is stored under, across all five protocols.
    ///
    /// The key that [`crate::storage::Storage::get_settings`] matches a config against
    /// (`pyatv/storage/__init__.py:102-111`).
    pub fn identifiers(&self) -> impl Iterator<Item = &str> {
        Protocol::ALL
            .into_iter()
            .filter_map(|protocol| self.identifier(protocol))
    }

    /// The credentials stored for one protocol.
    #[must_use]
    pub fn credentials(&self, protocol: Protocol) -> Option<&str> {
        match protocol {
            Protocol::AirPlay => self.airplay.credentials.as_deref(),
            Protocol::Companion => self.companion.credentials.as_deref(),
            Protocol::Dmap => self.dmap.credentials.as_deref(),
            Protocol::Mrp => self.mrp.credentials.as_deref(),
            Protocol::Raop => self.raop.credentials.as_deref(),
        }
    }

    /// Replace the credentials stored for one protocol.
    pub fn set_credentials(&mut self, protocol: Protocol, credentials: Option<String>) {
        match protocol {
            Protocol::AirPlay => self.airplay.credentials = credentials,
            Protocol::Companion => self.companion.credentials = credentials,
            Protocol::Dmap => self.dmap.credentials = credentials,
            Protocol::Mrp => self.mrp.credentials = credentials,
            Protocol::Raop => self.raop.credentials = credentials,
        }
    }

    /// The password stored for one protocol.
    ///
    /// Only `AirPlay` and RAOP have the field at all; the other three return `None` because
    /// upstream's models have no such key (`pyatv/settings.py:117-135`).
    #[must_use]
    pub fn password(&self, protocol: Protocol) -> Option<&str> {
        match protocol {
            Protocol::AirPlay => self.airplay.password.as_deref(),
            Protocol::Raop => self.raop.password.as_deref(),
            Protocol::Companion | Protocol::Dmap | Protocol::Mrp => None,
        }
    }

    /// Replace the password stored for one protocol, ignoring protocols that have no password.
    pub fn set_password(&mut self, protocol: Protocol, password: Option<String>) {
        match protocol {
            Protocol::AirPlay => self.airplay.password = password,
            Protocol::Raop => self.raop.password = password,
            Protocol::Companion | Protocol::Dmap | Protocol::Mrp => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolSettings, RaopSettings};
    use crate::consts::Protocol;

    /// A port out of `u16` range must cost that one setting, not the whole file.
    ///
    /// pyatv writes these as unbounded pydantic `int`s, so anything can legitimately end up in the
    /// file that both implementations share. Parsing them as `u16` made one bad value fail the
    /// entire deserialisation, taking every stored credential for every device with it.
    #[test]
    fn an_out_of_range_port_is_ignored_rather_than_refusing_the_file() {
        let settings: RaopSettings =
            serde_json::from_str(r#"{"timing_port": 70000, "control_port": 6002}"#)
                .expect("an unusable port must not fail the parse");

        assert_eq!(settings.timing(), None);
        assert_eq!(settings.control(), Some(6002));
    }

    /// Zero is pyatv's "pick a free one" sentinel (`settings.py:152-162`), not a real port.
    #[test]
    fn zero_means_pick_a_free_port() {
        let settings = RaopSettings::default();
        assert_eq!(settings.timing_port, 0);
        assert_eq!(settings.timing(), None);
        assert_eq!(settings.control(), None);
    }

    /// The five slots are addressed by protocol, and nothing leaks between them.
    #[test]
    fn every_protocol_has_its_own_identifier_and_credentials() {
        let mut protocols = ProtocolSettings::default();
        for protocol in Protocol::ALL {
            protocols.set_identifier(protocol, Some(format!("{protocol:?}-id")));
            protocols.set_credentials(protocol, Some(format!("{protocol:?}-creds")));
        }

        for protocol in Protocol::ALL {
            assert_eq!(
                protocols.identifier(protocol),
                Some(format!("{protocol:?}-id").as_str())
            );
            assert_eq!(
                protocols.credentials(protocol),
                Some(format!("{protocol:?}-creds").as_str())
            );
        }

        let identifiers: Vec<&str> = protocols.identifiers().collect();
        assert_eq!(identifiers.len(), Protocol::ALL.len());
    }

    /// Only `AirPlay` and RAOP have a password field upstream; setting one anywhere else must be
    /// dropped rather than invent a key pyatv's model would refuse to round-trip.
    #[test]
    fn only_airplay_and_raop_keep_a_password() {
        let mut protocols = ProtocolSettings::default();
        for protocol in Protocol::ALL {
            protocols.set_password(protocol, Some("hunter2".to_owned()));
        }

        assert_eq!(protocols.password(Protocol::AirPlay), Some("hunter2"));
        assert_eq!(protocols.password(Protocol::Raop), Some("hunter2"));
        assert_eq!(protocols.password(Protocol::Companion), None);
        assert_eq!(protocols.password(Protocol::Dmap), None);
        assert_eq!(protocols.password(Protocol::Mrp), None);
    }

    /// `identifiers()` skips the slots that hold nothing.
    #[test]
    fn identifiers_skips_empty_slots() {
        let mut protocols = ProtocolSettings::default();
        protocols.set_identifier(Protocol::Mrp, Some("mrp-id".to_owned()));

        assert_eq!(protocols.identifiers().collect::<Vec<_>>(), ["mrp-id"]);
    }
}
