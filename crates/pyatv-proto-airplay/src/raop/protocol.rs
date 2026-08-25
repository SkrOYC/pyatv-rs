//! Choosing between the two RAOP streaming protocols, and dispatching to the chosen one.
//!
//! `StreamProtocol` is an abstract base class upstream (`protocols/__init__.py:76-100`) with
//! exactly two implementations selected once at connect time. An enum expresses that better than a
//! trait object in Rust: the set is closed, the dispatch is a match, and neither variant's methods
//! have to be boxed.
//!
//! The choice itself is `get_protocol_version` (`pyatv/protocols/airplay/utils.py:241-259`), which
//! `play_url` and RAOP call with the *same* function but different services — RAOP passes its own
//! `_raop._tcp` service, whose `ft` key is consulted before `features`.

use pyatv_core::airplay::{AirPlayVersion, get_protocol_version};
use pyatv_core::models::BaseService;
use pyatv_pairing::HapCredentials;

pub use pyatv_core::airplay::AirPlayMajorVersion;

use crate::Result;
use crate::raop::connection::SharedConnection;
use crate::raop::context::StreamContext;
use crate::raop::packets::AudioPacketHeader;
use crate::raop::protocol_v1::AirPlayV1;
use crate::raop::protocol_v2::AirPlayV2;

/// Pick a protocol version from a RAOP service's advertised feature bits.
///
/// `get_protocol_version(service, settings.protocols.raop.protocol_version)`
/// (`raop/__init__.py:148-151`), with the setting at its default of
/// [`AirPlayVersion::Auto`]. The decision function is `pyatv-core`'s, because discovery needs it
/// too; what is RAOP-specific is only *which* service it is asked about — the `_raop._tcp` one,
/// whose `ft` key is consulted before `features`.
#[must_use]
pub fn protocol_version(service: &BaseService) -> AirPlayMajorVersion {
    get_protocol_version(service, AirPlayVersion::Auto)
}

/// The streaming protocol in use for one session.
#[derive(Debug)]
pub enum StreamProtocol {
    /// AirPlay 1.
    V1(Box<AirPlayV1>),
    /// AirPlay 2.
    V2(Box<AirPlayV2>),
}

impl StreamProtocol {
    /// Build the protocol a version calls for.
    #[must_use]
    pub fn new(version: AirPlayMajorVersion) -> Self {
        match version {
            AirPlayMajorVersion::V1 => Self::V1(Box::new(AirPlayV1::new())),
            // `AirPlayV2::default()` is `AirPlayV2::new()`, fresh session UUID and all.
            AirPlayMajorVersion::V2 => Self::V2(Box::default()),
        }
    }

    /// Which version this is.
    #[must_use]
    pub fn version(&self) -> AirPlayMajorVersion {
        match self {
            Self::V1(_) => AirPlayMajorVersion::V1,
            Self::V2(_) => AirPlayMajorVersion::V2,
        }
    }

    /// Bring the streaming session up.
    ///
    /// `StreamProtocol.setup(timing_server_port, control_client_port)`
    /// (`protocols/__init__.py:79-81`). The `password` is only meaningful on the AirPlay 1 path —
    /// upstream's AirPlay 2 `SETUP` never looks at `context.password`.
    ///
    /// # Errors
    ///
    /// Returns whatever the chosen version's own `setup` returns.
    pub async fn setup(
        &mut self,
        connection: &SharedConnection,
        context: &mut StreamContext,
        credentials: &HapCredentials,
        password: Option<&str>,
        timing_port: u16,
        control_port: u16,
    ) -> Result<()> {
        match self {
            Self::V1(protocol) => {
                protocol
                    .setup(
                        connection,
                        context,
                        credentials,
                        password,
                        timing_port,
                        control_port,
                    )
                    .await
            }
            Self::V2(protocol) => {
                protocol
                    .setup(connection, context, credentials, timing_port, control_port)
                    .await
            }
        }
    }

    /// Start whichever keepalive this version uses.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the AirPlay 1 probe cannot be sent. The AirPlay 2 loop
    /// cannot fail: it swallows everything, exactly as upstream's bare `except` does.
    pub async fn start_feedback(&mut self, connection: &SharedConnection) -> Result<()> {
        match self {
            Self::V1(protocol) => protocol.start_feedback(connection).await,
            Self::V2(protocol) => {
                protocol.start_feedback(connection);
                Ok(())
            }
        }
    }

    /// Release the resources `setup` allocated.
    pub fn teardown(&mut self) {
        match self {
            Self::V1(protocol) => protocol.teardown(),
            Self::V2(protocol) => protocol.teardown(),
        }
    }

    /// Build one audio packet, encrypting it if the version calls for that.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Pairing`] if the AirPlay 2 AEAD seal fails.
    pub fn audio_packet(&mut self, header: &AudioPacketHeader, audio: &[u8]) -> Result<Vec<u8>> {
        let encoded = header.encode();
        match self {
            Self::V1(_) => Ok(AirPlayV1::audio_packet(&encoded, audio)),
            Self::V2(protocol) => protocol.audio_packet(&encoded, audio, &header.additional_data()),
        }
    }
}

#[cfg(test)]
mod tests {
    use pyatv_core::consts::Protocol;
    use pyatv_core::models::BaseService;

    use super::{AirPlayMajorVersion, StreamProtocol, protocol_version};
    use crate::raop::packets::AudioPacketHeader;

    fn service(entries: &[(&str, &str)]) -> BaseService {
        let mut service = BaseService::new(Protocol::Raop, 7000);
        for (key, value) in entries {
            service
                .properties
                .insert((*key).to_owned(), (*value).to_owned());
        }
        service
    }

    /// The live test device's own value: bits 38 and 48 both set, so version 2 unambiguously.
    #[test]
    fn the_test_devices_features_select_airplay_two() {
        assert_eq!(
            protocol_version(&service(&[("ft", "0x4A7FDFD5,0x3C177FDE")])),
            AirPlayMajorVersion::V2
        );
    }

    /// A receiver advertising neither bit is an AirPlay 1 device.
    #[test]
    fn no_modern_bits_selects_airplay_one() {
        assert_eq!(
            protocol_version(&service(&[("ft", "0x5A7FFFF7,0x1E")])),
            AirPlayMajorVersion::V1
        );
        assert_eq!(protocol_version(&service(&[])), AirPlayMajorVersion::V1);
    }

    /// `ft` is consulted before `features`, not the other way round.
    #[test]
    fn the_ft_key_wins_over_features() {
        let service = service(&[("ft", "0x0,0x0"), ("features", "0x0,0x3C177FDE")]);

        assert_eq!(protocol_version(&service), AirPlayMajorVersion::V1);
    }

    /// A `features`-only service still resolves, which is the fallback branch.
    #[test]
    fn features_is_the_fallback_when_ft_is_absent() {
        assert_eq!(
            protocol_version(&service(&[("features", "0x4A7FDFD5,0x3C177FDE")])),
            AirPlayMajorVersion::V2
        );
    }

    /// A malformed TXT value reads as no flags rather than failing the connection.
    #[test]
    fn an_unparsable_feature_string_selects_airplay_one() {
        assert_eq!(
            protocol_version(&service(&[("ft", "not a bitmask")])),
            AirPlayMajorVersion::V1
        );
    }

    /// The AirPlay 1 packet is plaintext and exactly header-plus-payload long.
    #[test]
    fn the_version_one_packet_is_unencrypted() {
        let mut protocol = StreamProtocol::new(AirPlayMajorVersion::V1);
        let header = AudioPacketHeader::new(true, 1, 2, 3);

        let packet = protocol.audio_packet(&header, &[0xAA; 8]).expect("builds");

        assert_eq!(packet.len(), 12 + 8);
        assert_eq!(&packet[12..], &[0xAA; 8]);
        assert_eq!(protocol.version(), AirPlayMajorVersion::V1);
    }

    /// The AirPlay 2 packet cannot be built before `setup` has produced a cipher.
    #[test]
    fn the_version_two_packet_needs_a_cipher_first() {
        let mut protocol = StreamProtocol::new(AirPlayMajorVersion::V2);
        let header = AudioPacketHeader::new(true, 1, 2, 3);

        assert!(protocol.audio_packet(&header, &[0xAA; 8]).is_err());
    }
}
