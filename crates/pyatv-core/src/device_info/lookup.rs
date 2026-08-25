//! The model, internal-name and build-number lookup tables.
//!
//! A verbatim port of `pyatv/support/device_info.py` (whole file, 163 lines). The tables are the
//! only way pyatv learns what a device actually is: mDNS advertises a hardware identifier such as
//! `AppleTV6,2` and a build number such as `21K365`, never a marketing name or version.
//!
//! Upstream uses `re` for two patterns. Neither needs a regex engine:
//! `^(\d+)[A-Z]` is "leading digits followed by an uppercase letter", and the `_OS_IDENTIFIER_FORMATS`
//! entries are all "literal prefix, digits, comma, digits". Both are hand-parsed below, so this
//! crate takes no `regex` dependency.

use std::borrow::Cow;

use crate::consts::{DeviceModel, OperatingSystem};

/// Map a hardware identifier such as `AppleTV6,2` to a model.
///
/// Ports `_MODEL_LIST` and `lookup_model` (`pyatv/support/device_info.py:8-24,101-103`). The
/// argument is optional because upstream accepts `None` and answers
/// [`DeviceModel::Unknown`] for it.
#[must_use]
pub fn lookup_model(identifier: Option<&str>) -> DeviceModel {
    match identifier.unwrap_or_default() {
        "AirPort4,107" => DeviceModel::AirPortExpress,
        "AirPort10,115" => DeviceModel::AirPortExpressGen2,
        "AppleTV1,1" => DeviceModel::AppleTvGen1,
        "AppleTV2,1" => DeviceModel::Gen2,
        "AppleTV3,1" | "AppleTV3,2" => DeviceModel::Gen3,
        "AppleTV5,3" => DeviceModel::Gen4,
        "AppleTV6,2" => DeviceModel::Gen4K,
        "AppleTV11,1" => DeviceModel::AppleTv4KGen2,
        "AppleTV14,1" => DeviceModel::AppleTv4KGen3,
        "AudioAccessory1,1" | "AudioAccessory1,2" => DeviceModel::HomePod,
        "AudioAccessory5,1" | "AudioAccessorySingle5,1" => DeviceModel::HomePodMini,
        "AudioAccessory6,1" => DeviceModel::HomePodGen2,
        _ => DeviceModel::Unknown,
    }
}

/// Map an internal Apple board name such as `J105aAP` to a model.
///
/// Ports `_INTERNAL_NAME_LIST` and `lookup_internal_name`
/// (`pyatv/support/device_info.py:27-35,106-108`). These names come from the `model` key of the
/// `_device-info._tcp.local` TXT record, which is the only source for devices that do not
/// advertise a `AppleTVx,y` identifier anywhere else.
#[must_use]
pub fn lookup_internal_name(name: Option<&str>) -> DeviceModel {
    match name.unwrap_or_default() {
        "K66AP" => DeviceModel::Gen2,
        "J33AP" | "J33IAP" => DeviceModel::Gen3,
        "J42dAP" => DeviceModel::Gen4,
        "J105aAP" => DeviceModel::Gen4K,
        "J305AP" => DeviceModel::AppleTv4KGen2,
        "J255AP" => DeviceModel::AppleTv4KGen3,
        _ => DeviceModel::Unknown,
    }
}

/// Map a build number such as `21K365` to a marketing version such as `17.2`.
///
/// Ports `_VERSION_LIST` and `lookup_version` (`pyatv/support/device_info.py:38-89,111-127`).
///
/// Two things about this table are worth knowing before trusting a result:
///
/// - It is explicitly incomplete upstream ("Only Apple TV version numbers for now") and stops at
///   tvOS 18.1, so anything newer falls through to the approximation below.
/// - The approximation is `build[0..n] - 4`: build `17A123` is tvOS 13.x, `16A123` is 12.x, and so
///   on. It yields a `"<major>.x"` string, never a precise version.
///
/// Upstream oddity, reproduced deliberately: the entry for tvOS 17.0 is keyed `22J354`, while every
/// other 17.x build starts with `21` and `22J357` is separately mapped to 18.0. It looks like a
/// typo for `21J354`, but changing it would silently diverge from pyatv, so it is kept as-is.
#[must_use]
pub fn lookup_version(build: Option<&str>) -> Option<Cow<'static, str>> {
    let build = build.filter(|it| !it.is_empty())?;

    if let Some(version) = version_from_table(build) {
        return Some(Cow::Borrowed(version));
    }

    // `re.match(r"^(\d+)[A-Z]", build)`: leading digits, then one uppercase ASCII letter.
    let digits_len = build
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(build.len());
    if digits_len == 0 || !build[digits_len..].starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }

    // A build number's leading group is two or three digits in practice, so `i32` cannot overflow
    // for real input; a pathologically long run of digits simply yields no guess.
    let base: i32 = build[..digits_len].parse().ok()?;
    Some(Cow::Owned(format!("{}.x", base - 4)))
}

/// Guess the operating system from a hardware identifier such as `MacBookAir10,1`.
///
/// The `str` arm of `lookup_os` (`pyatv/support/device_info.py:130-143`). Only Macs are
/// recognisable this way; everything else is [`OperatingSystem::Unknown`] and has to go through
/// [`lookup_os_from_model`] instead.
#[must_use]
pub fn lookup_os_from_identifier(identifier: &str) -> OperatingSystem {
    // `_OS_IDENTIFIER_FORMATS` (`pyatv/support/device_info.py:91-98`). Upstream uses `re.match`,
    // which anchors at the start only, so a trailing suffix still matches.
    const MAC_PREFIXES: [&str; 6] = [
        "MacBookAir",
        "iMac",
        "Macmini",
        "MacBookPro",
        "Mac",
        "MacPro",
    ];

    if MAC_PREFIXES
        .iter()
        .any(|prefix| matches_hardware_identifier(identifier, prefix, false))
    {
        OperatingSystem::MacOs
    } else {
        OperatingSystem::Unknown
    }
}

/// Map a known model to the operating system it runs.
///
/// The [`DeviceModel`] arm of `lookup_os` (`pyatv/support/device_info.py:145-163`).
///
/// Note that this disagrees with [`super::DeviceInfo::operating_system`] on two models: here
/// `Gen2`/`Gen3` are [`OperatingSystem::Legacy`] (which is correct — they ran Apple TV Software,
/// not tvOS), while `DeviceInfo` reports them as [`OperatingSystem::TvOs`]. Both behaviours are
/// upstream's and both are asserted by upstream's own tests, so both are reproduced.
#[must_use]
pub fn lookup_os_from_model(model: DeviceModel) -> OperatingSystem {
    match model {
        DeviceModel::AirPortExpress | DeviceModel::AirPortExpressGen2 => OperatingSystem::AirPortOs,
        DeviceModel::HomePod | DeviceModel::HomePodMini | DeviceModel::HomePodGen2 => {
            OperatingSystem::TvOs
        }
        DeviceModel::AppleTvGen1 | DeviceModel::Gen2 | DeviceModel::Gen3 => OperatingSystem::Legacy,
        DeviceModel::Gen4
        | DeviceModel::Gen4K
        | DeviceModel::AppleTv4KGen2
        | DeviceModel::AppleTv4KGen3 => OperatingSystem::TvOs,
        DeviceModel::Unknown | DeviceModel::Music => OperatingSystem::Unknown,
    }
}

/// Whether `value` is `prefix` followed by `<digits>,<digits>`.
///
/// The shape shared by every `_OS_IDENTIFIER_FORMATS` entry and by
/// `pyatv/protocols/airplay/utils.py:34` (`UNSUPPORTED_MODELS`). `anchored_end` distinguishes the
/// two call sites: `lookup_os` uses `re.match` (start-anchored only), while `UNSUPPORTED_MODELS`
/// spells out `^Mac\d+,\d+$`.
pub(crate) fn matches_hardware_identifier(value: &str, prefix: &str, anchored_end: bool) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    let Some(rest) = strip_ascii_digits(rest) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(',') else {
        return false;
    };
    let Some(rest) = strip_ascii_digits(rest) else {
        return false;
    };
    !anchored_end || rest.is_empty()
}

/// Strip one or more leading ASCII digits, or `None` if there are none.
fn strip_ascii_digits(value: &str) -> Option<&str> {
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    if end == 0 { None } else { Some(&value[end..]) }
}

/// The literal `_VERSION_LIST` table.
fn version_from_table(build: &str) -> Option<&'static str> {
    let version = match build {
        "17J586" => "13.0",
        "17K82" => "13.2",
        "17K449" => "13.3",
        "17K795" => "13.3.1",
        "17L256" => "13.4",
        "17L562" => "13.4.5",
        "17L570" => "13.4.6",
        "17M61" => "13.4.8",
        "18J386" => "14.0",
        "18J400" => "14.0.1",
        "18J411" => "14.0.2",
        "18K57" => "14.2",
        "18K561" => "14.3",
        "18K802" => "14.4",
        "18L204" => "14.5",
        "18L569" => "14.6",
        "18M60" => "14.7",
        "19J346" => "15.0",
        "19J572" => "15.1",
        "19J581" => "15.1.1",
        "19K53" => "15.2",
        "19K547" => "15.3",
        "19L440" => "15.4",
        "19L452" => "15.4.1",
        "19L570" => "15.5",
        "19L580" => "15.5.1",
        "19M65" => "15.6",
        "20J373" => "16.0",
        "20K71" => "16.1",
        "20K80" => "16.1.1",
        "20K362" => "16.2",
        "20K650" => "16.3",
        "20K661" => "16.3.1",
        "20K672" => "16.3.2",
        "20K680" => "16.3.3",
        "20L497" => "16.4",
        "20L498" => "16.4.1",
        "20L563" => "16.5",
        "20M73" => "16.6",
        "22J354" => "17.0",
        "21K69" => "17.1",
        "21K365" => "17.2",
        "21K646" => "17.3",
        "21L227" => "17.4",
        "21L569" => "17.5",
        "21L580" => "17.5.1",
        "21M71" => "17.6",
        "21M80" => "17.6.1",
        "22J357" => "18.0",
        "22J580" => "18.1",
        _ => return None,
    };
    Some(version)
}

#[cfg(test)]
mod tests {
    use super::{
        lookup_internal_name, lookup_model, lookup_os_from_identifier, lookup_os_from_model,
        lookup_version, matches_hardware_identifier,
    };
    use crate::consts::{DeviceModel, OperatingSystem};

    /// Ports `tests/support/test_device_info.py::test_lookup_model`.
    #[test]
    fn lookup_model_matches_upstream() {
        assert_eq!(lookup_model(Some("AppleTV6,2")), DeviceModel::Gen4K);
        assert_eq!(
            lookup_model(Some("AudioAccessory5,1")),
            DeviceModel::HomePodMini
        );
        assert_eq!(lookup_model(Some("bad_model")), DeviceModel::Unknown);
        assert_eq!(lookup_model(None), DeviceModel::Unknown);
    }

    /// The remaining `_MODEL_LIST` rows, which upstream's test does not cover individually.
    #[test]
    fn lookup_model_covers_the_whole_table() {
        for (identifier, expected) in [
            ("AirPort4,107", DeviceModel::AirPortExpress),
            ("AirPort10,115", DeviceModel::AirPortExpressGen2),
            ("AppleTV1,1", DeviceModel::AppleTvGen1),
            ("AppleTV2,1", DeviceModel::Gen2),
            ("AppleTV3,1", DeviceModel::Gen3),
            ("AppleTV3,2", DeviceModel::Gen3),
            ("AppleTV5,3", DeviceModel::Gen4),
            ("AppleTV11,1", DeviceModel::AppleTv4KGen2),
            ("AppleTV14,1", DeviceModel::AppleTv4KGen3),
            ("AudioAccessory1,1", DeviceModel::HomePod),
            ("AudioAccessory1,2", DeviceModel::HomePod),
            ("AudioAccessorySingle5,1", DeviceModel::HomePodMini),
            ("AudioAccessory6,1", DeviceModel::HomePodGen2),
        ] {
            assert_eq!(lookup_model(Some(identifier)), expected, "{identifier}");
        }
    }

    /// Ports `tests/support/test_device_info.py::test_lookup_internal_name`.
    #[test]
    fn lookup_internal_name_matches_upstream() {
        assert_eq!(lookup_internal_name(Some("J105aAP")), DeviceModel::Gen4K);
        assert_eq!(lookup_internal_name(Some("bad_name")), DeviceModel::Unknown);
        assert_eq!(lookup_internal_name(None), DeviceModel::Unknown);
    }

    #[test]
    fn lookup_internal_name_covers_the_whole_table() {
        for (name, expected) in [
            ("K66AP", DeviceModel::Gen2),
            ("J33AP", DeviceModel::Gen3),
            ("J33IAP", DeviceModel::Gen3),
            ("J42dAP", DeviceModel::Gen4),
            ("J305AP", DeviceModel::AppleTv4KGen2),
            ("J255AP", DeviceModel::AppleTv4KGen3),
        ] {
            assert_eq!(lookup_internal_name(Some(name)), expected, "{name}");
        }
    }

    /// Ports `tests/support/test_device_info.py::test_lookup_existing_version`.
    #[test]
    fn lookup_version_matches_upstream() {
        assert_eq!(lookup_version(None), None);
        assert_eq!(lookup_version(Some("17J586")).as_deref(), Some("13.0"));
        assert_eq!(lookup_version(Some("bad_version")), None);
        assert_eq!(lookup_version(Some("16F123")).as_deref(), Some("12.x"));
        assert_eq!(lookup_version(Some("17F123")).as_deref(), Some("13.x"));
    }

    /// Python's `if not build` treats the empty string as missing.
    #[test]
    fn lookup_version_treats_empty_build_as_missing() {
        assert_eq!(lookup_version(Some("")), None);
    }

    /// The table wins over the `major - 4` approximation, which is why `22J354` maps to 17.0 and
    /// not to the 18.x its prefix would suggest.
    #[test]
    fn lookup_version_prefers_the_table_over_the_approximation() {
        assert_eq!(lookup_version(Some("22J354")).as_deref(), Some("17.0"));
        assert_eq!(lookup_version(Some("22J357")).as_deref(), Some("18.0"));
        assert_eq!(lookup_version(Some("22J999")).as_deref(), Some("18.x"));
    }

    /// Ports the string arm of `tests/support/test_device_info.py::test_lookup_os`.
    #[test]
    fn lookup_os_from_identifier_matches_upstream() {
        assert_eq!(lookup_os_from_identifier("bad"), OperatingSystem::Unknown);
        for identifier in [
            "MacBookAir10,1",
            "iMac1,2",
            "Macmini1,1",
            "MacBookPro5,67",
            "Mac1,4",
            "MacPro19,4",
        ] {
            assert_eq!(
                lookup_os_from_identifier(identifier),
                OperatingSystem::MacOs,
                "{identifier}"
            );
        }
    }

    /// An Apple TV identifier has the same shape but not a Mac prefix.
    #[test]
    fn lookup_os_from_identifier_ignores_non_macs() {
        assert_eq!(
            lookup_os_from_identifier("AppleTV6,2"),
            OperatingSystem::Unknown
        );
        assert_eq!(lookup_os_from_identifier("Mac"), OperatingSystem::Unknown);
        assert_eq!(lookup_os_from_identifier("Mac1"), OperatingSystem::Unknown);
        assert_eq!(lookup_os_from_identifier("Mac1,"), OperatingSystem::Unknown);
    }

    /// Ports the model arm of `tests/support/test_device_info.py::test_lookup_os`.
    #[test]
    fn lookup_os_from_model_matches_upstream() {
        for (model, expected) in [
            (DeviceModel::AirPortExpress, OperatingSystem::AirPortOs),
            (DeviceModel::AirPortExpressGen2, OperatingSystem::AirPortOs),
            (DeviceModel::HomePod, OperatingSystem::TvOs),
            (DeviceModel::HomePodGen2, OperatingSystem::TvOs),
            (DeviceModel::HomePodMini, OperatingSystem::TvOs),
            (DeviceModel::AppleTvGen1, OperatingSystem::Legacy),
            (DeviceModel::Gen2, OperatingSystem::Legacy),
            (DeviceModel::Gen3, OperatingSystem::Legacy),
            (DeviceModel::Gen4, OperatingSystem::TvOs),
            (DeviceModel::Gen4K, OperatingSystem::TvOs),
            (DeviceModel::AppleTv4KGen2, OperatingSystem::TvOs),
            (DeviceModel::AppleTv4KGen3, OperatingSystem::TvOs),
            (DeviceModel::Unknown, OperatingSystem::Unknown),
            (DeviceModel::Music, OperatingSystem::Unknown),
        ] {
            assert_eq!(lookup_os_from_model(model), expected, "{model:?}");
        }
    }

    #[test]
    fn hardware_identifier_matcher_honours_the_end_anchor() {
        assert!(matches_hardware_identifier("Mac1,4", "Mac", true));
        assert!(matches_hardware_identifier("Mac1,4extra", "Mac", false));
        assert!(!matches_hardware_identifier("Mac1,4extra", "Mac", true));
        assert!(!matches_hardware_identifier("MacBookAir10,1", "Mac", false));
    }
}
