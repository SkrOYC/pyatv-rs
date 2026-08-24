//! Settings that live only as long as the process.
//!
//! Ports `pyatv/storage/memory_storage.py`. This is the default every entry point falls back to
//! when the caller passes no storage (`pyatv/__init__.py:90,115,179`), which is why `scan()` and
//! `connect()` work at all without a settings file — they simply forget everything afterwards.

use crate::Result;
use crate::models::BaseConfig;
use crate::storage::Storage;
use crate::storage::core::StorageCore;
use crate::storage::settings::Settings;

/// Settings that live only as long as the process.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    core: StorageCore,
}

impl MemoryStorage {
    /// An empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    /// Nothing to read, so nothing happens (`memory_storage.py:19-20`).
    fn load(&self) -> Result<()> {
        Ok(())
    }

    /// Nothing to write; the change marker is updated so [`MemoryStorage`] reports the same
    /// "saved" state a real backend would (`memory_storage.py:15-17`).
    fn save(&self) -> Result<()> {
        let dumped = self.core.dump()?;
        self.core.mark_saved(dumped)
    }

    fn settings(&self) -> Result<Vec<Settings>> {
        self.core.settings()
    }

    fn get_settings(&self, config: &BaseConfig) -> Result<Settings> {
        self.core.get_settings(config)
    }

    fn find_settings(&self, identifier: &str) -> Result<Option<Settings>> {
        self.core.find_settings(identifier)
    }

    fn set_settings(&self, settings: Settings) -> Result<()> {
        self.core.set_settings(settings)
    }

    fn update_settings(&self, config: &BaseConfig) -> Result<()> {
        self.core.update_settings(config)
    }

    fn remove_settings(&self, settings: &Settings) -> Result<bool> {
        self.core.remove_settings(settings)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::MemoryStorage;
    use crate::consts::Protocol;
    use crate::models::{BaseConfig, BaseService};
    use crate::storage::Storage;

    #[test]
    fn credentials_survive_within_the_process() {
        let storage = MemoryStorage::new();
        let mut config = BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        let mut service = BaseService::new(Protocol::Mrp, 49152);
        service.identifier = Some("mrp-id".to_owned());
        config.add_service(service);

        storage.load().expect("load must succeed");
        storage
            .store_credentials("mrp-id", Protocol::Mrp, "aabb:ccdd")
            .expect("storing credentials must succeed");
        storage.save().expect("save must succeed");

        assert_eq!(
            storage
                .get_settings(&config)
                .expect("lookup must succeed")
                .protocols
                .credentials(Protocol::Mrp),
            Some("aabb:ccdd")
        );
    }

    /// `store_credentials` has to work before the device has ever been looked up, because the
    /// pairing handler may be the first thing that touches storage.
    #[test]
    fn store_credentials_creates_a_record_for_an_unknown_device() {
        let storage = MemoryStorage::new();
        storage
            .store_credentials("companion-id", Protocol::Companion, "creds")
            .expect("storing credentials must succeed");

        let stored = storage
            .find_settings("companion-id")
            .expect("readable")
            .expect("a record must have been created");
        assert_eq!(
            stored.protocols.credentials(Protocol::Companion),
            Some("creds")
        );
        assert_eq!(
            stored.protocols.identifier(Protocol::Companion),
            Some("companion-id")
        );
    }
}
