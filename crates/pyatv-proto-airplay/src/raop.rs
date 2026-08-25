//! RAOP: the audio streaming half of AirPlay.
//!
//! See `docs/research/airplay-raop-dmap.md` for the RTP packet layouts and the retransmit/control
//! channels, and `docs/research/rust-crates.md` §7 for the codec question.
//!
//! Audio properties are negotiated through the receiver's mDNS TXT records rather than being
//! hardcoded: `sr` for sample rate, `ch` for channel count and `ss` for sample size in bits. Those
//! keys reach here on the [`pyatv_core::BaseService::properties`] map that discovery populated.

pub mod connection;
pub mod context;
pub mod facade;
pub mod fifo;
pub mod manager;
pub mod metadata;
pub mod net;
pub mod pacing;
pub mod packets;
pub mod protocol;
pub mod protocol_v1;
pub mod protocol_v2;
pub mod rtsp;
pub mod stream;
pub mod timing;
pub mod volume;

use std::collections::HashMap;
use std::hash::BuildHasher;

use pyatv_core::BaseService;

pub use facade::{RaopSetupOptions, setup};
pub use protocol::{AirPlayMajorVersion, protocol_version};

/// Audio format the receiver asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioProperties {
    /// Sample rate in Hz, from the `sr` TXT key.
    pub sample_rate: u32,
    /// Channel count, from the `ch` TXT key.
    pub channels: u8,
    /// Bits per sample, from the `ss` TXT key.
    pub sample_size: u8,
}

impl Default for AudioProperties {
    /// pyatv's defaults for a receiver that advertises none of the three keys.
    fn default() -> Self {
        Self {
            sample_rate: 44_100,
            channels: 2,
            sample_size: 16,
        }
    }
}

impl AudioProperties {
    /// Read the audio properties out of a discovered service's TXT records, defaulting any key the
    /// receiver did not advertise.
    #[must_use]
    pub fn from_service(service: &BaseService) -> Self {
        // A closure cannot be generic over the parsed type, so this is a function.
        fn read<T: std::str::FromStr>(service: &BaseService, key: &str) -> Option<T> {
            service.property(key).and_then(|raw| raw.parse().ok())
        }

        let defaults = Self::default();
        Self {
            sample_rate: read(service, "sr").unwrap_or(defaults.sample_rate),
            channels: read(service, "ch").unwrap_or(defaults.channels),
            sample_size: read(service, "ss").unwrap_or(defaults.sample_size),
        }
    }

    /// The same, from a raw TXT map.
    ///
    /// `get_audio_properties` (`pyatv/protocols/raop/parsers.py:35-46`) is handed
    /// `core.service.properties` rather than the service itself
    /// (`stream_client.py:340-351`), and the streaming path only ever has the map.
    #[must_use]
    pub fn from_properties<S: BuildHasher>(properties: &HashMap<String, String, S>) -> Self {
        fn read<T: std::str::FromStr, S: BuildHasher>(
            properties: &HashMap<String, String, S>,
            key: &str,
        ) -> Option<T> {
            properties.get(key).and_then(|raw| raw.parse().ok())
        }

        let defaults = Self::default();
        Self {
            sample_rate: read(properties, "sr").unwrap_or(defaults.sample_rate),
            channels: read(properties, "ch").unwrap_or(defaults.channels),
            sample_size: read(properties, "ss").unwrap_or(defaults.sample_size),
        }
    }
}

// The encryption schemes a receiver advertises in `et` live in
// [`pyatv_core::airplay::EncryptionType`], which is the bitflags set `get_encryption_types` parses
// (`pyatv/protocols/raop/parsers.py`) and the one
// [`crate::raop::stream::SUPPORTED_ENCRYPTIONS`] intersects against. An enum here duplicated the
// same knowledge in a shape nothing could combine, so it is gone rather than kept in step.

#[cfg(test)]
mod tests {
    use pyatv_core::{BaseService, Protocol};

    use super::AudioProperties;

    #[test]
    fn missing_txt_keys_fall_back_to_pyatv_defaults() {
        let service = BaseService::new(Protocol::Raop, 7000);
        assert_eq!(
            AudioProperties::from_service(&service),
            AudioProperties {
                sample_rate: 44_100,
                channels: 2,
                sample_size: 16,
            }
        );
    }

    /// The receiver dictates the format, so advertised keys must win over the defaults.
    #[test]
    fn advertised_txt_keys_override_the_defaults() {
        let mut service = BaseService::new(Protocol::Raop, 7000);
        service
            .properties
            .insert("sr".to_owned(), "48000".to_owned());
        service.properties.insert("ch".to_owned(), "1".to_owned());

        let properties = AudioProperties::from_service(&service);
        assert_eq!(properties.sample_rate, 48_000);
        assert_eq!(properties.channels, 1);
        // Not advertised, so still the default.
        assert_eq!(properties.sample_size, 16);
    }

    /// An unparseable value must not panic or produce a nonsense rate.
    #[test]
    fn unparseable_txt_values_fall_back_rather_than_failing() {
        let mut service = BaseService::new(Protocol::Raop, 7000);
        service
            .properties
            .insert("sr".to_owned(), "not a number".to_owned());

        assert_eq!(AudioProperties::from_service(&service).sample_rate, 44_100);
    }
}
