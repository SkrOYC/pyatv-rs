//! Persistent settings and credentials.
//!
//! Equivalent to `pyatv/storage/`. Since pyatv v0.14.0 a successful pairing writes its credentials
//! straight into storage, so callers never handle credential strings by hand; this port keeps that
//! contract. The on-disk shape is a JSON document holding one [`DeviceSettings`] per device
//! identifier, so a file written here stays readable by pyatv's own `FileStorage` and vice versa.
//!
//! The trait is deliberately synchronous. pyatv's storage API is `async` only because Python's
//! ecosystem forces `aiofiles` on anyone who touches a file from an event loop; a credential store
//! is read once at connect time and written once at pair time, so blocking `std::fs` inside a
//! `spawn_blocking` at the call site is simpler than making the whole trait return futures.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::consts::Protocol;
use crate::error::Error;

/// Per-protocol settings and credentials for one device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolSettings {
    /// Credentials in pyatv's colon-separated lowercase-hex format.
    pub credentials: Option<String>,
    /// Password for services that demand one.
    pub password: Option<String>,
}

/// Everything persisted about a single device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSettings {
    /// Stable device identifier this record is keyed by.
    pub identifier: String,
    /// Last known human-readable name, for display only.
    pub name: Option<String>,
    /// Settings per protocol.
    pub protocols: HashMap<Protocol, ProtocolSettings>,
}

/// The whole persisted document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageModel {
    /// Schema version, so a future format change can migrate rather than fail.
    pub version: u32,
    /// One record per known device.
    pub devices: Vec<DeviceSettings>,
}

/// Reads and writes device settings.
pub trait Storage: Send + Sync + std::fmt::Debug {
    /// Load the settings for one device, or `None` if nothing is stored for it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the backing store could not be read or parsed.
    fn get_settings(&self, identifier: &str) -> Result<Option<DeviceSettings>>;

    /// Insert or replace the settings for one device and persist immediately.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the backing store could not be written.
    fn set_settings(&self, settings: DeviceSettings) -> Result<()>;

    /// Every device the store knows about.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the backing store could not be read or parsed.
    fn all_settings(&self) -> Result<Vec<DeviceSettings>>;
}

/// A [`Storage`] that keeps nothing beyond the current process.
///
/// The default when a caller does not supply one, matching pyatv's `MemoryStorage`.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    devices: std::sync::Mutex<HashMap<String, DeviceSettings>>,
}

impl MemoryStorage {
    /// An empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, DeviceSettings>>> {
        self.devices
            .lock()
            .map_err(|_| Error::Storage("in-memory storage mutex was poisoned".to_owned()))
    }
}

impl Storage for MemoryStorage {
    fn get_settings(&self, identifier: &str) -> Result<Option<DeviceSettings>> {
        Ok(self.lock()?.get(identifier).cloned())
    }

    fn set_settings(&self, settings: DeviceSettings) -> Result<()> {
        self.lock()?.insert(settings.identifier.clone(), settings);
        Ok(())
    }

    fn all_settings(&self) -> Result<Vec<DeviceSettings>> {
        Ok(self.lock()?.values().cloned().collect())
    }
}

/// Current on-disk schema version written by [`FileStorage`].
pub const STORAGE_VERSION: u32 = 1;

/// A [`Storage`] backed by a JSON file, equivalent to pyatv's `FileStorage`.
#[derive(Debug)]
pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    /// Use `path` as the backing file. The file is created on first write; a missing file reads as
    /// an empty store.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The conventional per-user location, `$HOME/.pyatv.conf`, matching pyatv's default so the two
    /// implementations can share a credential file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if no home directory could be determined.
    pub fn default_path() -> Result<PathBuf> {
        // TODO(step-1): fall back to the platform config directory on Windows, where pyatv uses
        // `%USERPROFILE%`. Reading `HOME` alone is correct on Linux and macOS only.
        std::env::var_os("HOME")
            .map(|home| Path::new(&home).join(".pyatv.conf"))
            .ok_or_else(|| Error::Storage("HOME is not set".to_owned()))
    }

    fn read(&self) -> Result<StorageModel> {
        match std::fs::read(&self.path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map_err(|error| Error::Storage(format!("could not parse settings file: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(StorageModel {
                version: STORAGE_VERSION,
                devices: Vec::new(),
            }),
            Err(error) => Err(Error::Io(error)),
        }
    }

    fn write(&self, model: &StorageModel) -> Result<()> {
        let raw = serde_json::to_vec_pretty(model)
            .map_err(|error| Error::Storage(format!("could not serialise settings: {error}")))?;

        // TODO(step-1): write to a sibling temporary file and rename over the target so a crash
        // mid-write cannot lose a user's credentials.
        std::fs::write(&self.path, raw).map_err(Error::Io)
    }
}

impl Storage for FileStorage {
    fn get_settings(&self, identifier: &str) -> Result<Option<DeviceSettings>> {
        Ok(self
            .read()?
            .devices
            .into_iter()
            .find(|device| device.identifier == identifier))
    }

    fn set_settings(&self, settings: DeviceSettings) -> Result<()> {
        let mut model = self.read()?;
        model.version = STORAGE_VERSION;
        match model
            .devices
            .iter_mut()
            .find(|device| device.identifier == settings.identifier)
        {
            Some(existing) => *existing = settings,
            None => model.devices.push(settings),
        }
        self.write(&model)
    }

    fn all_settings(&self) -> Result<Vec<DeviceSettings>> {
        Ok(self.read()?.devices)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceSettings, MemoryStorage, ProtocolSettings, Storage};
    use crate::consts::Protocol;

    #[test]
    fn memory_storage_round_trips_credentials() {
        let storage = MemoryStorage::new();
        let mut settings = DeviceSettings {
            identifier: "AA:BB:CC:DD:EE:FF".to_owned(),
            name: Some("Living Room".to_owned()),
            ..DeviceSettings::default()
        };
        settings.protocols.insert(
            Protocol::Mrp,
            ProtocolSettings {
                credentials: Some("aabb:ccdd:eeff:0011".to_owned()),
                password: None,
            },
        );

        storage.set_settings(settings.clone()).unwrap();

        assert_eq!(
            storage.get_settings("AA:BB:CC:DD:EE:FF").unwrap(),
            Some(settings)
        );
        assert_eq!(storage.get_settings("unknown").unwrap(), None);
        assert_eq!(storage.all_settings().unwrap().len(), 1);
    }
}
