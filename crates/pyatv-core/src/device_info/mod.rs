//! Hardware and firmware facts about a device, plus the tables they are derived from.
//!
//! [`DeviceInfo`] ports `pyatv/interface.py::DeviceInfo` (`pyatv/interface.py:952-1078`); the
//! lookup functions port `pyatv/support/device_info.py` in full. They live together because
//! `DeviceInfo` is not a plain record: three of its accessors *derive* their answer from the
//! tables when the device did not state the value outright.
//!
//! Discovery assembles the input incrementally — each protocol's scan handler contributes a few
//! keys, they are merged into one map, and the map becomes a `DeviceInfo`
//! (`pyatv/core/scan.py:248-249`). [`DeviceInfo::from_properties`] is the Rust shape of that
//! constructor.

mod lookup;

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::BuildHasher;

use serde::{Deserialize, Serialize};

use crate::consts::{DeviceModel, OperatingSystem};

pub(crate) use lookup::matches_hardware_identifier;
pub use lookup::{
    lookup_internal_name, lookup_model, lookup_os_from_identifier, lookup_os_from_model,
    lookup_version,
};

/// A value in the map [`DeviceInfo::from_properties`] consumes.
///
/// pyatv's `DeviceInfo(dict)` takes a heterogeneous `Mapping[str, Any]` and type-checks each key as
/// it pops it (`pyatv/interface.py:975-981`). This enum is that heterogeneity made explicit, so the
/// same wrong-type input is rejected at the same point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceInfoValue {
    /// An [`OperatingSystem`], valid only for [`DeviceInfo::OPERATING_SYSTEM`].
    OperatingSystem(OperatingSystem),
    /// A [`DeviceModel`], valid only for [`DeviceInfo::MODEL`].
    Model(DeviceModel),
    /// A string, valid for every other key.
    Text(String),
}

impl DeviceInfoValue {
    /// The name of the contained variant, for error messages.
    const fn type_name(&self) -> &'static str {
        match self {
            Self::OperatingSystem(_) => "OperatingSystem",
            Self::Model(_) => "DeviceModel",
            Self::Text(_) => "String",
        }
    }
}

impl From<&str> for DeviceInfoValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for DeviceInfoValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<OperatingSystem> for DeviceInfoValue {
    fn from(value: OperatingSystem) -> Self {
        Self::OperatingSystem(value)
    }
}

impl From<DeviceModel> for DeviceInfoValue {
    fn from(value: DeviceModel) -> Self {
        Self::Model(value)
    }
}

/// A key in the device-info map held a value of the wrong kind.
///
/// The equivalent of the `TypeError` raised by `_pop_with_type`
/// (`pyatv/interface.py:975-981`).
#[derive(Debug, thiserror::Error)]
#[error("expected {expected} for device info key '{field}' but got {actual}")]
pub struct DeviceInfoTypeError {
    /// The key whose value was rejected.
    pub field: &'static str,
    /// The type that key requires.
    pub expected: &'static str,
    /// The type that was supplied instead.
    pub actual: &'static str,
}

/// Hardware and firmware facts about a device.
///
/// Fields are private because three of the accessors are derived rather than stored: see
/// [`DeviceInfo::operating_system`], [`DeviceInfo::version`] and [`DeviceInfo::model_str`].
/// Exposing the raw fields would make it far too easy to read a stored `None` where upstream would
/// have answered with a derived value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    #[serde(rename = "os")]
    operating_system: OperatingSystem,
    version: Option<String>,
    build_number: Option<String>,
    model: DeviceModel,
    raw_model: Option<String>,
    mac: Option<String>,
    #[serde(rename = "airplay_id")]
    output_device_id: Option<String>,
}

impl DeviceInfo {
    /// Map key for the operating system. Verbatim from `pyatv/interface.py:955`.
    pub const OPERATING_SYSTEM: &'static str = "os";
    /// Map key for the marketing version. Verbatim from `pyatv/interface.py:956`.
    pub const VERSION: &'static str = "version";
    /// Map key for the build number. Verbatim from `pyatv/interface.py:957`.
    pub const BUILD_NUMBER: &'static str = "build_number";
    /// Map key for the resolved model. Verbatim from `pyatv/interface.py:958`.
    pub const MODEL: &'static str = "model";
    /// Map key for the raw, unresolved model string. Verbatim from `pyatv/interface.py:959`.
    pub const RAW_MODEL: &'static str = "raw_model";
    /// Map key for the MAC address. Verbatim from `pyatv/interface.py:960`.
    pub const MAC: &'static str = "mac";
    /// Map key for the `AirPlay` output device id.
    ///
    /// The constant is named `OUTPUT_DEVICE_ID` upstream but its string value is `"airplay_id"`
    /// (`pyatv/interface.py:961`) — the two do not match, and the string is what appears in the map.
    pub const OUTPUT_DEVICE_ID: &'static str = "airplay_id";

    /// Build a `DeviceInfo` from the map discovery assembles.
    ///
    /// Ports `DeviceInfo.__init__` (`pyatv/interface.py:963-981`). Keys the constructor does not
    /// know are ignored, exactly as upstream ignores whatever is left in `_devinfo` after popping.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceInfoTypeError`] when a key holds a value of the wrong kind, mirroring the
    /// `TypeError` upstream raises from `_pop_with_type`. Note that upstream does *not* type-check
    /// [`DeviceInfo::RAW_MODEL`] (it reads it straight back out of the leftover map rather than
    /// popping it); this port checks it, because the alternative is storing a value it could never
    /// render.
    pub fn from_properties<S: BuildHasher>(
        properties: &HashMap<String, DeviceInfoValue, S>,
    ) -> Result<Self, DeviceInfoTypeError> {
        fn text<S: BuildHasher>(
            properties: &HashMap<String, DeviceInfoValue, S>,
            field: &'static str,
        ) -> Result<Option<String>, DeviceInfoTypeError> {
            match properties.get(field) {
                None => Ok(None),
                Some(DeviceInfoValue::Text(value)) => Ok(Some(value.clone())),
                Some(other) => Err(DeviceInfoTypeError {
                    field,
                    expected: "String",
                    actual: other.type_name(),
                }),
            }
        }

        let operating_system = match properties.get(Self::OPERATING_SYSTEM) {
            None => OperatingSystem::Unknown,
            Some(DeviceInfoValue::OperatingSystem(value)) => *value,
            Some(other) => {
                return Err(DeviceInfoTypeError {
                    field: Self::OPERATING_SYSTEM,
                    expected: "OperatingSystem",
                    actual: other.type_name(),
                });
            }
        };
        let model = match properties.get(Self::MODEL) {
            None => DeviceModel::Unknown,
            Some(DeviceInfoValue::Model(value)) => *value,
            Some(other) => {
                return Err(DeviceInfoTypeError {
                    field: Self::MODEL,
                    expected: "DeviceModel",
                    actual: other.type_name(),
                });
            }
        };

        Ok(Self {
            operating_system,
            version: text(properties, Self::VERSION)?,
            build_number: text(properties, Self::BUILD_NUMBER)?,
            model,
            raw_model: text(properties, Self::RAW_MODEL)?,
            mac: text(properties, Self::MAC)?,
            output_device_id: text(properties, Self::OUTPUT_DEVICE_ID)?,
        })
    }

    /// Set the operating system explicitly, overriding the guess made from the model.
    #[must_use]
    pub fn with_operating_system(mut self, operating_system: OperatingSystem) -> Self {
        self.operating_system = operating_system;
        self
    }

    /// Set the marketing version explicitly, overriding the build-number lookup.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the build number.
    #[must_use]
    pub fn with_build_number(mut self, build_number: impl Into<String>) -> Self {
        self.build_number = Some(build_number.into());
        self
    }

    /// Set the resolved model.
    #[must_use]
    pub fn with_model(mut self, model: DeviceModel) -> Self {
        self.model = model;
        self
    }

    /// Set the raw model string the device advertised.
    #[must_use]
    pub fn with_raw_model(mut self, raw_model: impl Into<String>) -> Self {
        self.raw_model = Some(raw_model.into());
        self
    }

    /// Set the MAC address.
    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = Some(mac.into());
        self
    }

    /// Set the `AirPlay` output device identifier.
    #[must_use]
    pub fn with_output_device_id(mut self, output_device_id: impl Into<String>) -> Self {
        self.output_device_id = Some(output_device_id.into());
        self
    }

    /// Operating system running on the device.
    ///
    /// Ports `pyatv/interface.py:983-1004`. When the device did not state its OS, it is guessed
    /// from the model.
    ///
    /// Upstream oddity, reproduced deliberately: this guess maps `Gen2` and `Gen3` to
    /// [`OperatingSystem::TvOs`], even though those devices ran Apple TV Software and
    /// [`lookup_os_from_model`] correctly calls them [`OperatingSystem::Legacy`]. It also has no
    /// case for `HomePodGen2` or `AppleTvGen1`, which `lookup_os_from_model` does handle. Upstream
    /// asserts the `Gen2`/`Gen3` behaviour in `tests/test_interface.py::test_device_info_guess_os`,
    /// so it is kept.
    #[must_use]
    pub fn operating_system(&self) -> OperatingSystem {
        if self.operating_system != OperatingSystem::Unknown {
            return self.operating_system;
        }

        match self.model {
            DeviceModel::AirPortExpress | DeviceModel::AirPortExpressGen2 => {
                OperatingSystem::AirPortOs
            }
            DeviceModel::HomePod
            | DeviceModel::HomePodMini
            | DeviceModel::Gen2
            | DeviceModel::Gen3
            | DeviceModel::Gen4
            | DeviceModel::Gen4K
            | DeviceModel::AppleTv4KGen2
            | DeviceModel::AppleTv4KGen3 => OperatingSystem::TvOs,
            DeviceModel::Unknown
            | DeviceModel::HomePodGen2
            | DeviceModel::AppleTvGen1
            | DeviceModel::Music => OperatingSystem::Unknown,
        }
    }

    /// Operating system version, e.g. `17.2`.
    ///
    /// Ports `pyatv/interface.py:1006-1016`: the stated version wins, otherwise the build number is
    /// looked up, otherwise nothing.
    #[must_use]
    pub fn version(&self) -> Option<Cow<'_, str>> {
        if let Some(version) = self.version.as_deref().filter(|it| !it.is_empty()) {
            return Some(Cow::Borrowed(version));
        }
        lookup_version(self.build_number.as_deref())
    }

    /// Operating system build number, e.g. `21K365`.
    ///
    /// Ports `pyatv/interface.py:1018-1021`.
    #[must_use]
    pub fn build_number(&self) -> Option<&str> {
        self.build_number.as_deref()
    }

    /// Hardware model.
    ///
    /// Ports `pyatv/interface.py:1023-1026`.
    #[must_use]
    pub fn model(&self) -> DeviceModel {
        self.model
    }

    /// The model string the device advertised, when it could not be mapped to a [`DeviceModel`].
    ///
    /// Ports `pyatv/interface.py:1028-1035`.
    #[must_use]
    pub fn raw_model(&self) -> Option<&str> {
        self.raw_model.as_deref()
    }

    /// Model name for display, falling back to [`DeviceInfo::raw_model`].
    ///
    /// Ports `pyatv/interface.py:1037-1049`. The fallback only applies when the model is
    /// [`DeviceModel::Unknown`]; a recognised model always wins over the raw string.
    #[must_use]
    pub fn model_str(&self) -> &str {
        match self.raw_model.as_deref() {
            Some(raw_model) if self.model == DeviceModel::Unknown => raw_model,
            _ => self.model.as_str(),
        }
    }

    /// Device MAC address.
    ///
    /// Ports `pyatv/interface.py:1051-1054`. The value is passed through verbatim: upstream does no
    /// case or separator normalisation, so whatever the protocol's extractor produced is what
    /// appears here.
    #[must_use]
    pub fn mac(&self) -> Option<&str> {
        self.mac.as_deref()
    }

    /// `AirPlay` output device identifier.
    ///
    /// Ports `pyatv/interface.py:1056-1059`.
    #[must_use]
    pub fn output_device_id(&self) -> Option<&str> {
        self.output_device_id.as_deref()
    }
}

impl std::fmt::Display for DeviceInfo {
    /// Ports `pyatv/interface.py:1061-1078` (`DeviceInfo.__str__`), the `Model/SW:` line of
    /// `atvremote scan`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operating_system = match self.operating_system() {
            OperatingSystem::Legacy => "ATV SW",
            OperatingSystem::TvOs => "tvOS",
            OperatingSystem::AirPortOs => "AirPortOS",
            OperatingSystem::MacOs => "MacOS",
            OperatingSystem::Unknown => "Unknown OS",
        };
        write!(f, "{}, {operating_system}", self.model_str())?;

        if let Some(version) = self.version() {
            write!(f, " {version}")?;
        }
        if let Some(build_number) = self.build_number() {
            write!(f, " build {build_number}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
