//! The `AirPlay` feature bitmask and the major-version decision derived from it.
//!
//! Ports `pyatv/protocols/airplay/utils.py:37-118,237-259`.

use crate::models::BaseService;

bitflags::bitflags! {
    /// Features an `AirPlay` receiver advertises in its `features`/`ft` TXT key.
    ///
    /// Verbatim from `pyatv/protocols/airplay/utils.py:55-98`. Upstream's own comment is worth
    /// repeating: the bit meanings were imported from <https://emanuelecozzi.net/docs/airplay2/features/>
    /// and cross-checked against <https://openairplay.github.io/airplay-spec/features.html>, and the
    /// two sources disagree in places. Only the bit *indices* are load-bearing; treat the names as
    /// documentation.
    ///
    /// Names are transliterated to Rust's constant casing. The indices are unchanged, and
    /// `flags_match_upstream_indices` in this module's tests pins every one of them.
    ///
    /// Unknown bits are preserved rather than masked off, matching Python 3.11+ `IntFlag`, whose
    /// default boundary for `IntFlag` is `KEEP`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AirPlayFlags: u64 {
        /// `SupportsAirPlayVideoV1`.
        const SUPPORTS_AIRPLAY_VIDEO_V1 = 1 << 0;
        /// `SupportsAirPlayPhoto`.
        const SUPPORTS_AIRPLAY_PHOTO = 1 << 1;
        /// `SupportsAirPlaySlideShow`.
        const SUPPORTS_AIRPLAY_SLIDE_SHOW = 1 << 5;
        /// `SupportsAirPlayScreen`.
        const SUPPORTS_AIRPLAY_SCREEN = 1 << 7;
        /// `SupportsAirPlayAudio`.
        const SUPPORTS_AIRPLAY_AUDIO = 1 << 9;
        /// `AudioRedundant`.
        const AUDIO_REDUNDANT = 1 << 11;
        /// `Authentication_4`.
        const AUTHENTICATION_4 = 1 << 14;
        /// `MetadataFeatures_0`.
        const METADATA_FEATURES_0 = 1 << 15;
        /// `MetadataFeatures_1`.
        const METADATA_FEATURES_1 = 1 << 16;
        /// `MetadataFeatures_2`.
        const METADATA_FEATURES_2 = 1 << 17;
        /// `AudioFormats_0`.
        const AUDIO_FORMATS_0 = 1 << 18;
        /// `AudioFormats_1`.
        const AUDIO_FORMATS_1 = 1 << 19;
        /// `AudioFormats_2`.
        const AUDIO_FORMATS_2 = 1 << 20;
        /// `AudioFormats_3`.
        const AUDIO_FORMATS_3 = 1 << 21;
        /// `Authentication_1`.
        const AUTHENTICATION_1 = 1 << 23;
        /// `Authentication_8`.
        const AUTHENTICATION_8 = 1 << 26;
        /// `SupportsLegacyPairing`.
        const SUPPORTS_LEGACY_PAIRING = 1 << 27;
        /// `HasUnifiedAdvertiserInfo`.
        const HAS_UNIFIED_ADVERTISER_INFO = 1 << 30;
        /// `IsCarPlay`. Upstream notes this may really mean `SupportsVolume`.
        const IS_CAR_PLAY = 1 << 32;
        /// `SupportsAirPlayVideoPlayQueue`.
        const SUPPORTS_AIRPLAY_VIDEO_PLAY_QUEUE = 1 << 33;
        /// `SupportsAirPlayFromCloud`.
        const SUPPORTS_AIRPLAY_FROM_CLOUD = 1 << 34;
        /// `SupportsTLS_PSK`.
        const SUPPORTS_TLS_PSK = 1 << 35;
        /// `SupportsUnifiedMediaControl`. One of the two bits that mark an `AirPlay` 2 receiver.
        const SUPPORTS_UNIFIED_MEDIA_CONTROL = 1 << 38;
        /// `SupportsBufferedAudio`.
        const SUPPORTS_BUFFERED_AUDIO = 1 << 40;
        /// `SupportsPTP`.
        const SUPPORTS_PTP = 1 << 41;
        /// `SupportsScreenMultiCodec`.
        const SUPPORTS_SCREEN_MULTI_CODEC = 1 << 42;
        /// `SupportsSystemPairing`.
        const SUPPORTS_SYSTEM_PAIRING = 1 << 43;
        /// `IsAPValeriaScreenSender`.
        const IS_AP_VALERIA_SCREEN_SENDER = 1 << 44;
        /// `SupportsHKPairingAndAccessControl`.
        const SUPPORTS_HK_PAIRING_AND_ACCESS_CONTROL = 1 << 46;
        /// `SupportsCoreUtilsPairingAndEncryption`. The other `AirPlay` 2 marker bit.
        const SUPPORTS_CORE_UTILS_PAIRING_AND_ENCRYPTION = 1 << 48;
        /// `SupportsAirPlayVideoV2`.
        const SUPPORTS_AIRPLAY_VIDEO_V2 = 1 << 49;
        /// `MetadataFeatures_3`.
        const METADATA_FEATURES_3 = 1 << 50;
        /// `SupportsUnifiedPairSetupandMFi`.
        const SUPPORTS_UNIFIED_PAIR_SETUP_AND_MFI = 1 << 51;
        /// `SupportsSetPeersExtendedMessage`.
        const SUPPORTS_SET_PEERS_EXTENDED_MESSAGE = 1 << 52;
        /// `SupportsAPSync`.
        const SUPPORTS_AP_SYNC = 1 << 54;
        /// `SupportsWoL`.
        const SUPPORTS_WOL = 1 << 55;
        /// `SupportsWoL2`.
        const SUPPORTS_WOL2 = 1 << 56;
        /// `SupportsHangdogRemoteControl`.
        const SUPPORTS_HANGDOG_REMOTE_CONTROL = 1 << 58;
        /// `SupportsAudioStreamConnectionSetup`.
        const SUPPORTS_AUDIO_STREAM_CONNECTION_SETUP = 1 << 59;
        /// `SupportsAudioMetadataControl`.
        const SUPPORTS_AUDIO_METADATA_CONTROL = 1 << 60;
        /// `SupportsRFC2198Redundancy`.
        const SUPPORTS_RFC2198_REDUNDANCY = 1 << 61;
    }
}

/// A feature string did not have one of the two shapes upstream accepts.
///
/// The equivalent of the `ValueError` raised by `parse_features`
/// (`pyatv/protocols/airplay/utils.py:112-113`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid feature string: {0}")]
pub struct InvalidFeatureString(pub String);

/// Parse an `AirPlay` feature string.
///
/// Ports `parse_features` (`pyatv/protocols/airplay/utils.py:104-118`). Two shapes are accepted,
/// and only two:
///
/// - `0x12345678` — a single 32-bit word.
/// - `0x12345678,0xabcdef12` — **low word first**, so this is `0xabcdef1212345678`. Receivers
///   advertise the halves in that order and getting it backwards silently misreads every bit above
///   31, including the two that decide `AirPlay` 1 versus 2.
///
/// Upstream's regex is `^0x([0-9A-Fa-f]{1,8})(?:,0x([0-9A-Fa-f]{1,8})|)$`. It is fully anchored, so
/// a trailing comma, a leading comma or a third word are all rejected; each word is one to eight
/// hex digits. That is hand-parsed here rather than pulling in a regex engine.
///
/// # Errors
///
/// Returns [`InvalidFeatureString`] when the input does not match either shape.
pub fn parse_features(features: &str) -> Result<AirPlayFlags, InvalidFeatureString> {
    fn word(part: &str) -> Option<u64> {
        let digits = part.strip_prefix("0x")?;
        if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|it| it.is_ascii_hexdigit())
        {
            return None;
        }
        u64::from_str_radix(digits, 16).ok()
    }

    let invalid = || InvalidFeatureString(features.to_owned());

    let mut parts = features.split(',');
    let low = parts.next().and_then(word).ok_or_else(invalid)?;
    let value = match parts.next() {
        None => low,
        Some(high) => {
            let high = word(high).ok_or_else(invalid)?;
            // Deliberate divergence. Upstream concatenates the two capture groups as *text* and
            // parses once: `value = upper + value; int(value, 16)`
            // (`pyatv/protocols/airplay/utils.py:104-118`). Because its regex accepts one to eight
            // hex digits per word, a low word shorter than eight digits shifts the high word down
            // by the missing nibbles — `"0xE,0x1"` parses as `int("1E", 16) == 0x1E` upstream, not
            // as `0x1_0000_000E`.
            //
            // That is a bug, not a wire format: receivers always advertise both halves zero-padded
            // to eight digits (`sf`/`ft` are fixed-width 32-bit words), so for every real TXT
            // record the two readings agree bit for bit. Shifting is what the documented meaning
            // — "0x12345678,0xabcdef12 => 0xabcdef1212345678" — actually says, and it keeps a
            // short-but-legal string from silently landing bits in the wrong half. Pinned by
            // `parse_features_shifts_short_low_words`.
            (high << 32) | low
        }
    };
    if parts.next().is_some() {
        return Err(invalid());
    }

    // `IntFlag` keeps bits it has no name for; so does this.
    Ok(AirPlayFlags::from_bits_retain(value))
}

/// Which major `AirPlay` version to speak to a receiver.
///
/// Ports `AirPlayMajorVersion` (`pyatv/protocols/airplay/utils.py:37-41`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AirPlayMajorVersion {
    /// `AirPlay` 1.
    V1,
    /// `AirPlay` 2.
    V2,
}

/// The user's `AirPlay` version preference.
///
/// Ports `pyatv/settings.py:49-59` (`AirPlayVersion`). It lives here rather than in a settings
/// module because [`get_protocol_version`] is the only thing that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AirPlayVersion {
    /// Decide from the advertised feature bits.
    #[default]
    Auto,
    /// Force `AirPlay` 1.
    V1,
    /// Force `AirPlay` 2.
    V2,
}

/// Decide which major `AirPlay` version a service speaks.
///
/// Ports `get_protocol_version` (`pyatv/protocols/airplay/utils.py:241-259`), including its
/// preceding `TODO`: upstream does not actually know how to detect `AirPlay` 2 support and is
/// guessing. The guess is that the service advertises features (under `ft`, else `features`, else
/// `0x0`) and that bit 38 or bit 48 is set.
///
/// An unparseable feature string is treated as no features at all, i.e. `AirPlay` 1. Upstream
/// propagates the `ValueError` instead; a receiver with a malformed TXT record should not abort a
/// scan, so this port degrades rather than fails.
#[must_use]
pub fn get_protocol_version(
    service: &BaseService,
    preferred_version: AirPlayVersion,
) -> AirPlayMajorVersion {
    match preferred_version {
        AirPlayVersion::V2 => AirPlayMajorVersion::V2,
        AirPlayVersion::V1 => AirPlayMajorVersion::V1,
        AirPlayVersion::Auto => {
            let features = service
                .property("ft")
                .filter(|it| !it.is_empty())
                .or_else(|| service.property("features"))
                .unwrap_or("0x0");

            let parsed = parse_features(features).unwrap_or(AirPlayFlags::empty());
            if parsed.intersects(
                AirPlayFlags::SUPPORTS_UNIFIED_MEDIA_CONTROL
                    | AirPlayFlags::SUPPORTS_CORE_UTILS_PAIRING_AND_ENCRYPTION,
            ) {
                AirPlayMajorVersion::V2
            } else {
                AirPlayMajorVersion::V1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AirPlayFlags, AirPlayMajorVersion, AirPlayVersion, get_protocol_version, parse_features,
    };
    use crate::consts::Protocol;
    use crate::models::BaseService;

    fn service(properties: &[(&str, &str)]) -> BaseService {
        let mut service = BaseService::new(Protocol::AirPlay, 7000);
        for (key, value) in properties {
            service
                .properties
                .insert((*key).to_owned(), (*value).to_owned());
        }
        service
    }

    /// Every bit index, pinned against `pyatv/protocols/airplay/utils.py:58-98`.
    #[test]
    fn flags_match_upstream_indices() {
        let expected = [
            (AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V1, 0),
            (AirPlayFlags::SUPPORTS_AIRPLAY_PHOTO, 1),
            (AirPlayFlags::SUPPORTS_AIRPLAY_SLIDE_SHOW, 5),
            (AirPlayFlags::SUPPORTS_AIRPLAY_SCREEN, 7),
            (AirPlayFlags::SUPPORTS_AIRPLAY_AUDIO, 9),
            (AirPlayFlags::AUDIO_REDUNDANT, 11),
            (AirPlayFlags::AUTHENTICATION_4, 14),
            (AirPlayFlags::METADATA_FEATURES_0, 15),
            (AirPlayFlags::METADATA_FEATURES_1, 16),
            (AirPlayFlags::METADATA_FEATURES_2, 17),
            (AirPlayFlags::AUDIO_FORMATS_0, 18),
            (AirPlayFlags::AUDIO_FORMATS_1, 19),
            (AirPlayFlags::AUDIO_FORMATS_2, 20),
            (AirPlayFlags::AUDIO_FORMATS_3, 21),
            (AirPlayFlags::AUTHENTICATION_1, 23),
            (AirPlayFlags::AUTHENTICATION_8, 26),
            (AirPlayFlags::SUPPORTS_LEGACY_PAIRING, 27),
            (AirPlayFlags::HAS_UNIFIED_ADVERTISER_INFO, 30),
            (AirPlayFlags::IS_CAR_PLAY, 32),
            (AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_PLAY_QUEUE, 33),
            (AirPlayFlags::SUPPORTS_AIRPLAY_FROM_CLOUD, 34),
            (AirPlayFlags::SUPPORTS_TLS_PSK, 35),
            (AirPlayFlags::SUPPORTS_UNIFIED_MEDIA_CONTROL, 38),
            (AirPlayFlags::SUPPORTS_BUFFERED_AUDIO, 40),
            (AirPlayFlags::SUPPORTS_PTP, 41),
            (AirPlayFlags::SUPPORTS_SCREEN_MULTI_CODEC, 42),
            (AirPlayFlags::SUPPORTS_SYSTEM_PAIRING, 43),
            (AirPlayFlags::IS_AP_VALERIA_SCREEN_SENDER, 44),
            (AirPlayFlags::SUPPORTS_HK_PAIRING_AND_ACCESS_CONTROL, 46),
            (AirPlayFlags::SUPPORTS_CORE_UTILS_PAIRING_AND_ENCRYPTION, 48),
            (AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V2, 49),
            (AirPlayFlags::METADATA_FEATURES_3, 50),
            (AirPlayFlags::SUPPORTS_UNIFIED_PAIR_SETUP_AND_MFI, 51),
            (AirPlayFlags::SUPPORTS_SET_PEERS_EXTENDED_MESSAGE, 52),
            (AirPlayFlags::SUPPORTS_AP_SYNC, 54),
            (AirPlayFlags::SUPPORTS_WOL, 55),
            (AirPlayFlags::SUPPORTS_WOL2, 56),
            (AirPlayFlags::SUPPORTS_HANGDOG_REMOTE_CONTROL, 58),
            (AirPlayFlags::SUPPORTS_AUDIO_STREAM_CONNECTION_SETUP, 59),
            (AirPlayFlags::SUPPORTS_AUDIO_METADATA_CONTROL, 60),
            (AirPlayFlags::SUPPORTS_RFC2198_REDUNDANCY, 61),
        ];

        assert_eq!(expected.len(), 41, "upstream declares 41 named bits");
        for (flag, index) in expected {
            assert_eq!(flag.bits(), 1_u64 << index, "bit {index}");
        }
    }

    /// Ports `tests/protocols/airplay/test_utils.py::test_parse_features`.
    #[test]
    fn parse_features_matches_upstream() {
        assert_eq!(
            parse_features("0x00000001").expect("valid"),
            AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V1
        );
        assert_eq!(
            parse_features("0x40000003").expect("valid"),
            AirPlayFlags::HAS_UNIFIED_ADVERTISER_INFO
                | AirPlayFlags::SUPPORTS_AIRPLAY_PHOTO
                | AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V1
        );
        assert_eq!(
            parse_features("0x00000003,0x00000001").expect("valid"),
            AirPlayFlags::IS_CAR_PLAY
                | AirPlayFlags::SUPPORTS_AIRPLAY_PHOTO
                | AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V1
        );
    }

    /// Pins the deliberate divergence documented in [`parse_features`]: the high word is shifted
    /// by a fixed 32 bits, where upstream's string concatenation would shift it by however many
    /// hex digits the low word happened to have.
    ///
    /// `"0xE,0x1"` is `int("1E", 16) == 0x1E` in pyatv and `0x1_0000_000E` here. No real receiver
    /// emits an unpadded word, so the difference is unreachable in practice.
    #[test]
    fn parse_features_shifts_short_low_words() {
        assert_eq!(
            parse_features("0xE,0x1").expect("valid").bits(),
            0x1_0000_000E
        );
        assert_ne!(parse_features("0xE,0x1").expect("valid").bits(), 0x1E);

        // Zero-padded — the shape every receiver actually advertises — agrees with upstream.
        assert_eq!(
            parse_features("0x0000000E,0x00000001")
                .expect("valid")
                .bits(),
            0x1_0000_000E
        );
    }

    /// Ports `tests/protocols/airplay/test_utils.py::test_bad_input`.
    #[test]
    fn parse_features_rejects_malformed_strings() {
        for value in [
            "foo",
            "1234",
            "0x00000001,",
            ",0x00000001",
            "0x00000001,0x00000001,0x00000001",
        ] {
            assert!(parse_features(value).is_err(), "{value}");
        }
    }

    /// Nine hex digits exceeds the `{1,8}` upstream allows.
    #[test]
    fn parse_features_rejects_oversized_words() {
        assert!(parse_features("0x000000001").is_err());
        assert!(parse_features("0x1,0x000000001").is_err());
    }

    /// Bits with no name must survive the round trip, as Python's `IntFlag` keeps them.
    #[test]
    fn parse_features_retains_unnamed_bits() {
        // Bit 2 has no name upstream.
        let parsed = parse_features("0x00000004").expect("valid");
        assert_eq!(parsed.bits(), 0b100);
    }

    /// Ports `tests/protocols/airplay/test_utils.py::test_get_protocol_version`.
    #[test]
    fn get_protocol_version_matches_upstream() {
        let cases = [
            (vec![], AirPlayVersion::Auto, AirPlayMajorVersion::V1),
            // Apple TV 3, advertised under the RAOP key.
            (
                vec![("ft", "0x5A7FFFF7,0xE")],
                AirPlayVersion::Auto,
                AirPlayMajorVersion::V1,
            ),
            // HomePod Mini.
            (
                vec![("ft", "0x4A7FCA00,0xBC354BD0")],
                AirPlayVersion::Auto,
                AirPlayMajorVersion::V2,
            ),
            (
                vec![("features", "0x5A7FFFF7,0xE")],
                AirPlayVersion::Auto,
                AirPlayMajorVersion::V1,
            ),
            (
                vec![("features", "0x5A7FFFF7,0xE")],
                AirPlayVersion::V2,
                AirPlayMajorVersion::V2,
            ),
            (
                vec![("features", "0x4A7FCA00,0xBC354BD0")],
                AirPlayVersion::Auto,
                AirPlayMajorVersion::V2,
            ),
            (
                vec![("features", "0x4A7FCA00,0xBC354BD0")],
                AirPlayVersion::V1,
                AirPlayMajorVersion::V1,
            ),
        ];

        for (properties, preferred, expected) in cases {
            let service = service(&properties);
            assert_eq!(
                get_protocol_version(&service, preferred),
                expected,
                "{properties:?} {preferred:?}"
            );
        }
    }

    /// `ft` wins over `features` when both are present.
    #[test]
    fn get_protocol_version_prefers_ft_over_features() {
        let service = service(&[("ft", "0x1"), ("features", "0x0,0x40")]);
        assert_eq!(
            get_protocol_version(&service, AirPlayVersion::Auto),
            AirPlayMajorVersion::V1
        );
    }

    /// A malformed TXT record must not abort the scan.
    #[test]
    fn get_protocol_version_degrades_on_malformed_features() {
        let service = service(&[("features", "garbage")]);
        assert_eq!(
            get_protocol_version(&service, AirPlayVersion::Auto),
            AirPlayMajorVersion::V1
        );
    }
}
