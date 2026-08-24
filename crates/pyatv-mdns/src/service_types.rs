//! The DNS-SD service types pyatv browses for.
//!
//! Transcribed from each protocol's `__init__.py`; see `docs/research/pyatv-architecture.md` §3.
//! Two of these are not protocol-specific: `_device-info._tcp` enriches every device's
//! [`pyatv_core::DeviceInfo`], and `_sleep-proxy._udp` reveals devices that are asleep behind a
//! Bonjour sleep proxy.

use pyatv_core::Protocol;

/// One DNS-SD service type, and which protocol it implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// `_mediaremotetv._tcp.local` — MRP.
    MediaRemoteTv,
    /// `_companion-link._tcp.local` — Companion.
    CompanionLink,
    /// `_airplay._tcp.local` — AirPlay.
    AirPlay,
    /// `_raop._tcp.local` — RAOP audio.
    Raop,
    /// `_airport._tcp.local` — enriches AirPort Express device info; implies RAOP.
    AirPort,
    /// `_appletv-v2._tcp.local` — DMAP via Home Sharing.
    AppleTvV2,
    /// `_touch-able._tcp.local` — DMAP.
    TouchAble,
    /// `_hscp._tcp.local` — DMAP.
    Hscp,
    /// `_device-info._tcp.local` — device-info enrichment, no protocol of its own.
    DeviceInfo,
    /// `_sleep-proxy._udp.local` — sleep-proxy detection, no protocol of its own.
    SleepProxy,
}

impl ServiceType {
    /// Every service type pyatv browses, in the order it registers them.
    pub const ALL: [Self; 10] = [
        Self::MediaRemoteTv,
        Self::CompanionLink,
        Self::AirPlay,
        Self::Raop,
        Self::AirPort,
        Self::AppleTvV2,
        Self::TouchAble,
        Self::Hscp,
        Self::DeviceInfo,
        Self::SleepProxy,
    ];

    /// The fully qualified DNS-SD name, as passed to `ServiceDaemon::browse`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MediaRemoteTv => "_mediaremotetv._tcp.local.",
            Self::CompanionLink => "_companion-link._tcp.local.",
            Self::AirPlay => "_airplay._tcp.local.",
            Self::Raop => "_raop._tcp.local.",
            Self::AirPort => "_airport._tcp.local.",
            Self::AppleTvV2 => "_appletv-v2._tcp.local.",
            Self::TouchAble => "_touch-able._tcp.local.",
            Self::Hscp => "_hscp._tcp.local.",
            Self::DeviceInfo => "_device-info._tcp.local.",
            Self::SleepProxy => "_sleep-proxy._udp.local.",
        }
    }

    /// The protocol this service type provides, if any.
    #[must_use]
    pub const fn protocol(self) -> Option<Protocol> {
        Some(match self {
            Self::MediaRemoteTv => Protocol::Mrp,
            Self::CompanionLink => Protocol::Companion,
            Self::AirPlay => Protocol::AirPlay,
            Self::Raop | Self::AirPort => Protocol::Raop,
            Self::AppleTvV2 | Self::TouchAble | Self::Hscp => Protocol::Dmap,
            Self::DeviceInfo | Self::SleepProxy => return None,
        })
    }

    /// Match a browsed service type string back onto a known variant.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        let normalised = if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        };
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == normalised)
    }
}

#[cfg(test)]
mod tests {
    use pyatv_core::Protocol;

    use super::ServiceType;

    /// Both `_raop._tcp` and `_airport._tcp` map onto RAOP; the latter only adds device info for
    /// AirPort Express hardware.
    #[test]
    fn airport_and_raop_share_a_protocol() {
        assert_eq!(ServiceType::Raop.protocol(), Some(Protocol::Raop));
        assert_eq!(ServiceType::AirPort.protocol(), Some(Protocol::Raop));
    }

    /// All three DMAP service types map onto one protocol.
    #[test]
    fn every_dmap_service_type_maps_to_dmap() {
        for service in [
            ServiceType::AppleTvV2,
            ServiceType::TouchAble,
            ServiceType::Hscp,
        ] {
            assert_eq!(service.protocol(), Some(Protocol::Dmap));
        }
    }

    /// The enrichment-only types must not create a service on the config.
    #[test]
    fn enrichment_types_have_no_protocol() {
        assert_eq!(ServiceType::DeviceInfo.protocol(), None);
        assert_eq!(ServiceType::SleepProxy.protocol(), None);
    }

    #[test]
    fn round_trips_through_its_wire_name_with_or_without_a_trailing_dot() {
        for service in ServiceType::ALL {
            assert_eq!(ServiceType::from_wire_name(service.as_str()), Some(service));
            assert_eq!(
                ServiceType::from_wire_name(service.as_str().trim_end_matches('.')),
                Some(service)
            );
        }
        assert_eq!(ServiceType::from_wire_name("_http._tcp.local."), None);
    }
}
