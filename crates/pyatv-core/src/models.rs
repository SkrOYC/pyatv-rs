//! Device, service and playback data models.
//!
//! Equivalent to pyatv's `interface.BaseConfig`/`interface.BaseService` (plus `conf.AppleTV` and
//! `core.MutableService`), collapsed into plain structs. pyatv needs abstract base classes here
//! because Python has no way to express "a config the scanner mutates while building it, then
//! hands out immutably"; in Rust ownership already expresses that, so [`BaseConfig`] is a concrete
//! struct that the scanner builds and the caller consumes.
//!
//! See `docs/research/pyatv-architecture.md` §4 for the upstream contract these mirror.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::consts::{
    DeviceModel, DeviceState, MediaType, OperatingSystem, PairingRequirement, Protocol,
    RepeatState, ShuffleState,
};

/// One protocol's connection details for a single physical device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseService {
    /// Protocol-specific device identifier, as advertised over mDNS.
    pub identifier: Option<String>,
    /// Which protocol this service speaks.
    pub protocol: Protocol,
    /// TCP or UDP port, read from the mDNS SRV record — never hardcoded.
    pub port: u16,
    /// Whether the user has enabled this service for use.
    pub enabled: bool,
    /// Whether the device demands a password before this service can be used.
    pub requires_password: bool,
    /// Whether the service must be paired before use.
    pub pairing: PairingRequirement,
    /// Raw mDNS TXT record properties, lowercased keys.
    pub properties: HashMap<String, String>,
    /// Credentials previously negotiated for this service, in pyatv's colon-separated hex format.
    pub credentials: Option<String>,
    /// Password for services that require one.
    pub password: Option<String>,
}

impl BaseService {
    /// A minimal service with no credentials and everything else defaulted.
    #[must_use]
    pub fn new(protocol: Protocol, port: u16) -> Self {
        Self {
            identifier: None,
            protocol,
            port,
            enabled: true,
            requires_password: false,
            pairing: PairingRequirement::Unsupported,
            properties: HashMap::new(),
            credentials: None,
            password: None,
        }
    }

    /// Fold another discovery result for the same protocol into this one.
    ///
    /// Discovery sees the same device through several mDNS service types, so the scanner merges
    /// partial views rather than replacing them: non-empty fields on `other` win, empty ones are
    /// left alone.
    // TODO(step-1): mirror `BaseService.merge` precedence exactly, including the credential and
    // password handover rules described in docs/research/pyatv-architecture.md §4.
    pub fn merge(&mut self, other: &Self) {
        let _ = other;
        todo!("BaseService::merge")
    }
}

/// A single physical device and every protocol service discovered on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseConfig {
    /// Human-readable device name from the mDNS instance name.
    pub name: String,
    /// Address the device answered from.
    pub address: IpAddr,
    /// Hardware and OS details merged from every service's device-info extractor.
    pub device_info: DeviceInfo,
    /// Every discovered service, at most one per protocol.
    pub services: Vec<BaseService>,
}

impl BaseConfig {
    /// The service for a given protocol, if the device advertises one.
    #[must_use]
    pub fn get_service(&self, protocol: Protocol) -> Option<&BaseService> {
        self.services.iter().find(|s| s.protocol == protocol)
    }

    /// The stable identifier for this device, preferring the highest-priority service that has one.
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.services.iter().find_map(|s| s.identifier.as_deref())
    }

    /// The service that should drive the connection when the caller does not pick one.
    // TODO(step-1): reproduce pyatv's `main_service` priority order (MRP > DMAP > AirPlay > RAOP,
    // filtered by `enabled`), see docs/research/pyatv-architecture.md §4.
    #[must_use]
    pub fn main_service(&self) -> Option<&BaseService> {
        todo!("BaseConfig::main_service")
    }
}

/// Hardware and firmware facts about a device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Operating system family.
    pub operating_system: OperatingSystem,
    /// Marketing version string, e.g. `17.2`.
    pub version: Option<String>,
    /// Build number, e.g. `21K365`.
    pub build_number: Option<String>,
    /// Hardware model.
    pub model: DeviceModel,
    /// Primary MAC address, colon-separated uppercase hex.
    pub mac: Option<String>,
    /// Raw model string when [`DeviceInfo::model`] could not be mapped to a known variant.
    pub raw_model: Option<String>,
}

/// An installed application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    /// Display name.
    pub name: String,
    /// Bundle identifier, e.g. `com.apple.TVMovies`.
    pub identifier: String,
}

/// A user account on the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    /// Display name.
    pub name: String,
    /// Opaque account identifier.
    pub identifier: String,
}

/// Artwork for the currently playing item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtworkInfo {
    /// Raw encoded image bytes.
    pub bytes: Vec<u8>,
    /// MIME type of [`ArtworkInfo::bytes`].
    pub mimetype: String,
    /// Pixel width, when the device reports it.
    pub width: Option<u32>,
    /// Pixel height, when the device reports it.
    pub height: Option<u32>,
}

/// A snapshot of what the device is playing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Playing {
    /// Kind of media.
    pub media_type: MediaType,
    /// Transport state.
    pub device_state: DeviceState,
    /// Item title.
    pub title: Option<String>,
    /// Performing artist.
    pub artist: Option<String>,
    /// Album name.
    pub album: Option<String>,
    /// Genre.
    pub genre: Option<String>,
    /// Total duration in seconds.
    pub total_time: Option<u32>,
    /// Current position in seconds.
    pub position: Option<u32>,
    /// Shuffle mode.
    pub shuffle: Option<ShuffleState>,
    /// Repeat mode.
    pub repeat: Option<RepeatState>,
    /// Series name for TV content.
    pub series_name: Option<String>,
    /// Season number for TV content.
    pub season_number: Option<u32>,
    /// Episode number for TV content.
    pub episode_number: Option<u32>,
    /// Opaque content identifier.
    pub content_identifier: Option<String>,
    /// iTunes Store identifier, added upstream in v0.16.0.
    pub itunes_store_identifier: Option<i64>,
}
