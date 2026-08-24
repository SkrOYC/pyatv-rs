//! Persistent settings and credentials.
//!
//! Ports `pyatv/storage/`, and deliberately ports it byte-for-byte: the document written here is
//! the same `~/.pyatv.conf` pyatv writes, so a user who has already paired with pyatv keeps their
//! credentials, and one who pairs here can go back. The shape is defined in [`settings`], the
//! shared logic in [`core`](self::core), and the two backends in [`file`] and [`memory`].
//!
//! ```text
//! StorageModel { version: 1, devices: [Settings] }
//!   Settings { info: InfoSettings, protocols: ProtocolSettings }
//!     ProtocolSettings { airplay, companion, dmap, mrp, raop }
//! ```
//!
//! Since pyatv v0.14.0 a successful pairing writes its credentials straight into storage, so
//! callers never handle credential strings by hand; this port keeps that contract.
//!
//! # Two deliberate differences from upstream
//!
//! **The trait is synchronous.** pyatv's storage API is `async` only because Python's ecosystem
//! forces `run_in_executor` on anyone who touches a file from an event loop; a credential store is
//! read once at connect time and written once at pair time, so blocking `std::fs` — inside a
//! `spawn_blocking` at the call site, if the caller cares — is simpler than making every method
//! return a future and forcing an `async_trait`-shaped allocation on implementors.
//!
//! **`get_settings` returns a clone.** Upstream returns a live reference into the store and lets
//! callers mutate it in place (`pyatv/storage/__init__.py:86-90`). A `&self` method behind a lock
//! cannot lend that reference out, so a modified record goes back through
//! [`Storage::set_settings`], and the common case — a pairing handler filing one credential
//! string — has [`Storage::store_credentials`] to do both halves.
//!
//! # Lifecycle
//!
//! Nothing is read or written implicitly. Call [`Storage::load`] once at start up and
//! [`Storage::save`] once at exit, which is exactly what `atvremote` does
//! (`pyatv/scripts/atvremote.py:715-736`). In between, every operation is in memory, and `save`
//! is a no-op when nothing changed.

pub mod core;
pub mod file;
pub mod json;
pub mod memory;
pub mod protocols;
pub mod settings;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::consts::Protocol;
use crate::models::BaseConfig;

pub use file::FileStorage;
pub use memory::MemoryStorage;
pub use protocols::{
    AirPlaySettings, CompanionSettings, DmapSettings, MrpSettings, ProtocolSettings, RaopSettings,
};
pub use settings::{InfoSettings, MrpTunnel, Settings};

/// Schema version this build reads and writes.
///
/// `MODEL_VERSION` (`pyatv/storage/__init__.py:22`). A document with any other version is refused
/// rather than guessed at.
pub const MODEL_VERSION: u32 = 1;

/// The document a backend persists.
///
/// Ports `StorageModel` (`pyatv/storage/__init__.py:36-40`). Both fields are required on load:
/// upstream's model declares them without defaults, so a file missing either is invalid.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageModel {
    /// Schema version, checked against [`MODEL_VERSION`] on load.
    pub version: u32,
    /// One record per known device.
    pub devices: Vec<Settings>,
}

/// Reads and writes device settings.
///
/// Ports the `Storage` abstract base class (`pyatv/interface.py:1470-1511`) plus the two
/// identifier-keyed helpers this port needs in place of upstream's live references, described in
/// the module docs.
pub trait Storage: Send + Sync + std::fmt::Debug {
    /// Read the backing store into memory.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Storage`] if the document could not be parsed or its version is not
    /// [`MODEL_VERSION`], or [`crate::Error::Io`] if it could not be read.
    fn load(&self) -> Result<()>;

    /// Write the in-memory settings back, if anything changed since the last save.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the document could not be written.
    fn save(&self) -> Result<()>;

    /// Settings for every known device.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Storage`] if the store could not be read.
    fn settings(&self) -> Result<Vec<Settings>>;

    /// Settings for one device, created on the spot if this is the first time it is seen.
    ///
    /// A config matches a record when any one of its per-protocol identifiers matches any
    /// identifier the record holds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::DeviceIdMissing`] if the config has no identifier — which is the
    /// case for a device that has not been discovered, since identifiers come from mDNS.
    fn get_settings(&self, config: &BaseConfig) -> Result<Settings>;

    /// The record filed under `identifier`, matched against every protocol's identifier.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Storage`] if the store could not be read.
    fn find_settings(&self, identifier: &str) -> Result<Option<Settings>>;

    /// File a record back, replacing whichever record shares an identifier with it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Storage`] if the store could not be written.
    fn set_settings(&self, settings: Settings) -> Result<()>;

    /// Copy credentials, passwords and identifiers out of a config and into storage.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::DeviceIdMissing`] if the config has no identifier.
    fn update_settings(&self, config: &BaseConfig) -> Result<()>;

    /// Forget a device, reporting whether there was anything to forget.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Storage`] if the store could not be written.
    fn remove_settings(&self, settings: &Settings) -> Result<bool>;

    /// Store one protocol's credentials for the device known by `identifier`.
    ///
    /// What a pairing handler calls on success. Upstream instead assigns to the live `Settings`
    /// object it was constructed with (`pyatv/protocols/companion/pairing.py:66`,
    /// `pyatv/protocols/airplay/pairing.py:80-84`); this is the same effect through a `&self`
    /// API. If the device is not yet known — pairing can be the first thing that ever touches
    /// storage — a record is created with `identifier` filed under `protocol`.
    ///
    /// Like every other method here it does not persist on its own; call [`Storage::save`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Storage`] if the store could not be read or written.
    fn store_credentials(
        &self,
        identifier: &str,
        protocol: Protocol,
        credentials: &str,
    ) -> Result<()> {
        let mut settings = self.find_settings(identifier)?.unwrap_or_else(|| {
            let mut settings = Settings::default();
            settings
                .protocols
                .set_identifier(protocol, Some(identifier.to_owned()));
            settings
        });

        settings
            .protocols
            .set_credentials(protocol, Some(credentials.to_owned()));
        self.set_settings(settings)
    }
}
