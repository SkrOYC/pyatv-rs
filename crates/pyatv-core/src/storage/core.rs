//! The storage logic every backend shares.
//!
//! Ports `pyatv/storage/__init__.py::AbstractStorage` (`pyatv/storage/__init__.py:43-179`), which
//! owns everything except the actual persistence: the in-memory list of [`Settings`], lookup by
//! config, creation of a record for an unseen device, and the change detection that lets `save()`
//! do nothing when nothing moved.
//!
//! Upstream's `get_settings` hands back a *live reference* into that list, so a caller — a pairing
//! handler, say — mutates storage simply by assigning to the object it was given. Rust cannot lend
//! a reference out of a `&self` method guarded by a lock, so this port returns clones and takes the
//! modified record back through [`StorageCore::set_settings`]. That is the one structural
//! difference from upstream, and it is why [`crate::storage::Storage`] has a `set_settings` method
//! at all.

use std::sync::Mutex;

use crate::Result;
use crate::error::Error;
use crate::models::BaseConfig;
use crate::storage::json::to_python_json;
use crate::storage::settings::Settings;
use crate::storage::{MODEL_VERSION, StorageModel};

/// The dump of an empty model, used as the "nothing has been saved yet" marker.
///
/// Upstream seeds its hash with `_dict_hash({})` (`pyatv/storage/__init__.py:53`), a value no real
/// dump can produce, so the first `save()` always writes.
const NOTHING_SAVED: &str = "{}";

/// Everything a [`crate::storage::Storage`] implementation needs beyond its own I/O.
#[derive(Debug)]
pub struct StorageCore {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    settings: Vec<Settings>,
    /// The document as it is believed to exist in the backing store.
    saved: String,
}

impl Default for StorageCore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                settings: Vec::new(),
                saved: NOTHING_SAVED.to_owned(),
            }),
        }
    }
}

impl StorageCore {
    /// An empty store that has never been saved.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    ///
    /// Returns [`Error::Storage`] if another thread panicked while holding the lock.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| Error::Storage("settings lock was poisoned".to_owned()))
    }

    /// Settings for every known device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn settings(&self) -> Result<Vec<Settings>> {
        Ok(self.lock()?.settings.clone())
    }

    /// Replace the whole document, rejecting a version this build does not understand.
    ///
    /// Ports the `storage_model` setter (`pyatv/storage/__init__.py:73-78`), whose only validation
    /// is the version check — down to the wording of the error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if `model.version` is not [`MODEL_VERSION`], or if the lock is
    /// poisoned.
    pub fn set_model(&self, model: StorageModel) -> Result<()> {
        if model.version != MODEL_VERSION {
            return Err(Error::Storage(format!(
                "unsupported version: {}",
                model.version
            )));
        }

        self.lock()?.settings = model.devices;
        Ok(())
    }

    /// The whole document, ready to be written out.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn model(&self) -> Result<StorageModel> {
        Ok(StorageModel {
            version: MODEL_VERSION,
            devices: self.lock()?.settings.clone(),
        })
    }

    /// The document serialised exactly as pyatv would write it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned or serialisation fails.
    pub fn dump(&self) -> Result<String> {
        let model = self.model()?;
        to_python_json(&model)
            .map_err(|error| Error::Storage(format!("could not serialise settings: {error}")))
    }

    /// Whether `dumped` differs from what the backing store is believed to hold.
    ///
    /// Ports `has_changed` (`pyatv/storage/__init__.py:55-61`). Upstream compares SHA-256 digests
    /// of the JSON; comparing the JSON itself is the same predicate without the hashing, and the
    /// documents involved are a few hundred bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn has_changed(&self, dumped: &str) -> Result<bool> {
        Ok(self.lock()?.saved != dumped)
    }

    /// Record that `dumped` is now what the backing store holds.
    ///
    /// Ports `update_hash` (`pyatv/storage/__init__.py:80-82`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn mark_saved(&self, dumped: String) -> Result<()> {
        self.lock()?.saved = dumped;
        Ok(())
    }

    /// Settings for one device, creating a record for it if this is the first sighting.
    ///
    /// Ports `get_settings` (`pyatv/storage/__init__.py:84-117`): a config matches a record when
    /// *any* of the config's per-protocol identifiers matches *any* identifier the record holds,
    /// because a device answers under a different identifier on each protocol and a scan may not
    /// have seen all of them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DeviceIdMissing`] if the config carries no identifier at all, which is
    /// the case for a device that has not been discovered yet.
    pub fn get_settings(&self, config: &BaseConfig) -> Result<Settings> {
        let identifiers = config.all_identifiers();
        if identifiers.is_empty() {
            return Err(Error::DeviceIdMissing(config.name.clone()));
        }

        let mut inner = self.lock()?;
        if let Some(existing) = inner
            .settings
            .iter()
            .find(|settings| settings.matches_any(&identifiers))
        {
            return Ok(existing.clone());
        }

        let mut settings = Settings::default();
        update_from_config(config, &mut settings);
        inner.settings.push(settings.clone());
        Ok(settings)
    }

    /// The record filed under `identifier`, if there is one.
    ///
    /// Not an upstream method: pyatv's pairing handlers hold the live `Settings` object they were
    /// constructed with, whereas this port's handlers hold only the identifier they are pairing.
    /// The match is the same as [`StorageCore::get_settings`]', i.e. against every protocol's
    /// identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn find_settings(&self, identifier: &str) -> Result<Option<Settings>> {
        Ok(self
            .lock()?
            .settings
            .iter()
            .find(|settings| settings.matches_any(&[identifier]))
            .cloned())
    }

    /// File `settings` back, replacing whichever record shares an identifier with it.
    ///
    /// The write half of the clone-and-return contract described in the module docs. A record with
    /// no identifier in common with anything stored is appended.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn set_settings(&self, settings: Settings) -> Result<()> {
        let identifiers: Vec<&str> = settings.protocols.identifiers().collect();
        let mut inner = self.lock()?;

        let existing = inner
            .settings
            .iter_mut()
            .find(|stored| stored.matches_any(&identifiers));

        match existing {
            Some(stored) => *stored = settings,
            None => inner.settings.push(settings),
        }
        Ok(())
    }

    /// Pull credentials, passwords and identifiers out of `config` and back into storage.
    ///
    /// Ports `update_settings` (`pyatv/storage/__init__.py:129-136`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::DeviceIdMissing`] if the config carries no identifier.
    pub fn update_settings(&self, config: &BaseConfig) -> Result<()> {
        let mut settings = self.get_settings(config)?;
        update_from_config(config, &mut settings);
        self.set_settings(settings)
    }

    /// Forget a device.
    ///
    /// Ports `remove_settings` (`pyatv/storage/__init__.py:119-127`) and its return value: `true`
    /// when something was removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the lock is poisoned.
    pub fn remove_settings(&self, settings: &Settings) -> Result<bool> {
        let mut inner = self.lock()?;
        let before = inner.settings.len();
        inner.settings.retain(|stored| stored != settings);
        Ok(inner.settings.len() != before)
    }
}

/// Copy what a discovered config knows into a settings record.
///
/// Ports `_update_settings_from_config` (`pyatv/storage/__init__.py:138-166`) including its two
/// asymmetries, both of which matter:
///
/// - the identifier is assigned unconditionally, so a service without one clears the stored value;
/// - credentials and passwords go through `model_copy(update=...)` filtered by
///   `pyatv/support/pydantic_compat.py:21-29`, which drops `None` values — so a service with no
///   credentials leaves whatever is already stored alone.
fn update_from_config(config: &BaseConfig, settings: &mut Settings) {
    for service in &config.services {
        let protocol = service.protocol;

        if let Some(credentials) = service.credentials.clone() {
            settings
                .protocols
                .set_credentials(protocol, Some(credentials));
        }
        if let Some(password) = service.password.clone() {
            settings.protocols.set_password(protocol, Some(password));
        }
        settings
            .protocols
            .set_identifier(protocol, service.identifier.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::StorageCore;
    use crate::consts::Protocol;
    use crate::models::{BaseConfig, BaseService};
    use crate::storage::{MODEL_VERSION, StorageModel};

    fn config(services: &[(Protocol, Option<&str>)]) -> BaseConfig {
        let mut config = BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        for (protocol, identifier) in services {
            let mut service = BaseService::new(*protocol, 7000);
            service.identifier = identifier.map(ToOwned::to_owned);
            config.add_service(service);
        }
        config
    }

    #[test]
    fn a_config_without_identifiers_is_refused() {
        let core = StorageCore::new();
        let error = core
            .get_settings(&config(&[(Protocol::Mrp, None)]))
            .expect_err("a config with no identifier must not be stored");

        assert!(matches!(error, crate::Error::DeviceIdMissing(name) if name == "Living Room"));
    }

    #[test]
    fn the_first_lookup_creates_exactly_one_record() {
        let core = StorageCore::new();
        let config = config(&[(Protocol::Dmap, Some("id"))]);

        let settings = core.get_settings(&config).expect("lookup must succeed");
        assert_eq!(settings.protocols.identifier(Protocol::Dmap), Some("id"));
        assert_eq!(core.settings().expect("readable").len(), 1);

        core.get_settings(&config).expect("lookup must succeed");
        assert_eq!(core.settings().expect("readable").len(), 1);
    }

    /// A device is matched by *any* of its identifiers, not only the main one.
    #[test]
    fn a_record_is_found_through_a_secondary_protocols_identifier() {
        let core = StorageCore::new();
        core.get_settings(&config(&[
            (Protocol::AirPlay, Some("airplay-id")),
            (Protocol::Companion, Some("companion-id")),
        ]))
        .expect("lookup must succeed");

        // A later scan that only saw Companion still finds the same record.
        core.get_settings(&config(&[(Protocol::Companion, Some("companion-id"))]))
            .expect("lookup must succeed");

        assert_eq!(core.settings().expect("readable").len(), 1);
        assert!(
            core.find_settings("airplay-id")
                .expect("readable")
                .is_some()
        );
    }

    #[test]
    fn update_settings_keeps_stored_credentials_when_the_config_has_none() {
        let core = StorageCore::new();
        let mut config = config(&[(Protocol::Companion, Some("id"))]);

        let mut settings = core.get_settings(&config).expect("lookup must succeed");
        settings
            .protocols
            .set_credentials(Protocol::Companion, Some("stored".to_owned()));
        core.set_settings(settings).expect("write must succeed");

        core.update_settings(&config).expect("update must succeed");
        assert_eq!(
            core.find_settings("id").expect("readable").and_then(|it| it
                .protocols
                .credentials(Protocol::Companion)
                .map(str::to_owned)),
            Some("stored".to_owned())
        );

        // …but a config that *does* carry credentials overwrites them.
        config
            .get_service_mut(Protocol::Companion)
            .expect("service")
            .credentials = Some("fresh".to_owned());
        core.update_settings(&config).expect("update must succeed");
        assert_eq!(
            core.find_settings("id").expect("readable").and_then(|it| it
                .protocols
                .credentials(Protocol::Companion)
                .map(str::to_owned)),
            Some("fresh".to_owned())
        );
    }

    #[test]
    fn remove_settings_reports_whether_it_removed_anything() {
        let core = StorageCore::new();
        let settings = core
            .get_settings(&config(&[(Protocol::Mrp, Some("id"))]))
            .expect("lookup must succeed");

        assert!(
            core.remove_settings(&settings)
                .expect("removal must succeed")
        );
        assert!(
            !core
                .remove_settings(&settings)
                .expect("removal must succeed")
        );
        assert!(core.settings().expect("readable").is_empty());
    }

    #[test]
    fn a_foreign_model_version_is_rejected() {
        let core = StorageCore::new();
        let error = core
            .set_model(StorageModel {
                version: MODEL_VERSION + 1,
                devices: Vec::new(),
            })
            .expect_err("a future version must not be loaded");

        assert!(error.to_string().contains("unsupported version: 2"));
    }

    #[test]
    fn change_detection_starts_dirty_and_settles_after_a_save() {
        let core = StorageCore::new();
        let dumped = core.dump().expect("serialising must succeed");

        assert!(core.has_changed(&dumped).expect("readable"));
        core.mark_saved(dumped.clone()).expect("writable");
        assert!(!core.has_changed(&dumped).expect("readable"));
    }
}
