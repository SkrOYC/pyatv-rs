//! Settings persisted to a JSON file.
//!
//! Ports `pyatv/storage/file_storage.py`. The default path is `$HOME/.pyatv.conf` — literally the
//! same file pyatv uses, not a Rust-specific sibling — and the bytes written are what
//! `json.dumps(dumped) + "\n"` produces, so the two implementations can share one file without
//! either rewriting the other's formatting.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::Error;
use crate::models::BaseConfig;
use crate::storage::core::StorageCore;
use crate::storage::settings::Settings;
use crate::storage::{Storage, StorageModel};

/// Settings persisted to a JSON file.
///
/// Nothing is read or written until [`Storage::load`] and [`Storage::save`] are called; in
/// between, every operation is in memory, exactly as upstream's storage works.
#[derive(Debug)]
pub struct FileStorage {
    path: PathBuf,
    core: StorageCore,
}

impl FileStorage {
    /// Use `path` as the backing file.
    ///
    /// A file that does not exist reads as an empty store and is created by the first
    /// [`Storage::save`] that has something to write.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            core: StorageCore::new(),
        }
    }

    /// The backing file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The conventional per-user location, `$HOME/.pyatv.conf`.
    ///
    /// `FileStorage.default_storage` (`pyatv/storage/file_storage.py:25-36`) uses `Path.home()`,
    /// which is `%USERPROFILE%` on Windows and `$HOME` elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if no home directory could be determined.
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));

        home.map(|home| Path::new(&home).join(".pyatv.conf"))
            .ok_or_else(|| Error::Storage("neither HOME nor USERPROFILE is set".to_owned()))
    }
}

impl Storage for FileStorage {
    /// Read the file, if it exists.
    ///
    /// Ports `load` (`pyatv/storage/file_storage.py:50-62`), including the subtlety in its
    /// comment: the "already saved" marker is taken from the *file's own text*, not from
    /// re-serialising the parsed model, so that any normalisation the parse performed — a missing
    /// `rp_id` filled in, an unknown key dropped — shows up as a change and gets written back.
    fn load(&self) -> Result<()> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(Error::Io(error)),
        };

        let model: StorageModel = serde_json::from_str(&raw).map_err(|error| {
            Error::Storage(format!("could not parse {}: {error}", self.path.display()))
        })?;

        self.core.set_model(model)?;
        self.core.mark_saved(raw.trim_end().to_owned())
    }

    /// Write the file, but only if something actually changed.
    ///
    /// Ports `save` (`pyatv/storage/file_storage.py:38-48`), trailing newline included.
    fn save(&self) -> Result<()> {
        let dumped = self.core.dump()?;
        if !self.core.has_changed(&dumped)? {
            return Ok(());
        }

        tracing::debug!(path = %self.path.display(), "saving settings");
        write_atomically(&self.path, &dumped)?;
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

/// Write `contents` (plus the trailing newline pyatv writes) through a temporary file.
///
/// Upstream truncates the real file and writes into it (`file_storage.py:46-48`), which loses
/// every stored credential if the process dies mid-write. Renaming a complete sibling into place
/// is atomic on every platform this targets and costs nothing.
///
/// Two things the rename dance has to get right, and did not:
///
/// * **Permissions.** A fresh temporary file is created at whatever the umask allows, typically
///   `0644`, and the rename carries that mode onto the real file — so a settings file the user had
///   locked down to `0600` quietly became world-readable the first time anything was saved into
///   it. This file holds every device credential. [`apply_permissions`] copies the existing file's
///   mode across, or uses `0600` when creating one.
/// * **Durability.** Renaming a file whose contents are still in the page cache is atomic with
///   respect to *other processes*, not with respect to a crash: the rename can reach the disk
///   before the data does, leaving a file that is present and empty. [`std::fs::File::sync_all`]
///   before the rename is what makes the guarantee real.
fn write_atomically(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;

    let temporary = path.with_extension("conf.tmp");
    let mut file = std::fs::File::create(&temporary).map_err(Error::Io)?;

    // The permissions go on before a single byte of credential does, so there is no window in
    // which the file is both readable and non-empty.
    let written = apply_permissions(&file, path)
        .and_then(|()| file.write_all(contents.as_bytes()))
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    drop(file);

    if let Err(error) = written {
        drop(std::fs::remove_file(&temporary));
        return Err(Error::Io(error));
    }

    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            // Leaving the half-written sibling behind would be worse than the failed save.
            drop(std::fs::remove_file(&temporary));
            Err(Error::Io(error))
        }
    }
}

/// Give the temporary file the mode the real file already has, or `0600` if there is no real file.
///
/// `0600` rather than the umask default because this file stores pairing credentials: on a shared
/// machine, `0644` hands every local account the ability to control the user's Apple TV. pyatv
/// itself does not do this — it writes with plain `open(..., "w")` — but pyatv also never creates
/// the file with anything other than the umask, so matching it would mean matching a weakness.
#[cfg(unix)]
fn apply_permissions(file: &std::fs::File, path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    /// Owner read/write only.
    const CREDENTIALS_MODE: u32 = 0o600;

    let mode = match std::fs::metadata(path) {
        Ok(metadata) => metadata.permissions().mode() & 0o7777,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CREDENTIALS_MODE,
        Err(error) => return Err(error),
    };

    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Windows has no mode bits to carry across, and its ACL inheritance already does the right thing
/// for a file created inside the user's profile.
#[cfg(not(unix))]
fn apply_permissions(_file: &std::fs::File, _path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::FileStorage;
    use crate::consts::Protocol;
    use crate::models::{BaseConfig, BaseService};
    use crate::storage::Storage;

    /// A scratch directory that cleans itself up, so the tests need no dev-dependency.
    pub(super) struct TempDir(std::path::PathBuf);

    impl TempDir {
        pub(super) fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("pyatv-rs-storage-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&path));
            std::fs::create_dir_all(&path).expect("scratch directory must be creatable");
            Self(path)
        }

        pub(super) fn file(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    pub(super) fn config(identifier: &str) -> BaseConfig {
        let mut config = BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        let mut service = BaseService::new(Protocol::Companion, 49153);
        service.identifier = Some(identifier.to_owned());
        service.credentials = Some("creds".to_owned());
        config.add_service(service);
        config
    }

    #[test]
    fn a_missing_file_loads_as_an_empty_store() {
        let dir = TempDir::new("missing");
        let storage = FileStorage::new(dir.file("absent.conf"));

        storage.load().expect("a missing file must not be an error");
        assert!(storage.settings().expect("readable").is_empty());
    }

    #[test]
    fn saving_creates_the_file_and_reloading_returns_the_same_settings() {
        let dir = TempDir::new("roundtrip");
        let path = dir.file("settings.conf");

        let storage = FileStorage::new(&path);
        storage.load().expect("load must succeed");
        storage
            .update_settings(&config("companion-id"))
            .expect("update must succeed");
        storage.save().expect("save must succeed");

        let written = std::fs::read_to_string(&path).expect("the file must exist");
        assert!(written.ends_with('\n'), "pyatv writes a trailing newline");
        assert!(written.starts_with(r#"{"version": 1, "devices": ["#));

        let reloaded = FileStorage::new(&path);
        reloaded.load().expect("load must succeed");
        let settings = reloaded.settings().expect("readable");
        assert_eq!(settings.len(), 1);
        assert_eq!(
            settings[0].protocols.credentials(Protocol::Companion),
            Some("creds")
        );
    }

    #[test]
    fn saving_an_unchanged_store_does_not_touch_the_file() {
        let dir = TempDir::new("unchanged");
        let path = dir.file("settings.conf");

        let storage = FileStorage::new(&path);
        storage
            .update_settings(&config("companion-id"))
            .expect("update must succeed");
        storage.save().expect("save must succeed");

        // Deleting the file is the sharpest possible probe: a second save that writes anything at
        // all would put it back.
        std::fs::remove_file(&path).expect("the file must be removable");

        storage.save().expect("save must succeed");
        assert!(
            !path.exists(),
            "an unchanged store must not be written again"
        );
    }

    #[test]
    fn a_future_version_is_refused() {
        let dir = TempDir::new("version");
        let path = dir.file("settings.conf");
        std::fs::write(&path, r#"{"version": 99, "devices": []}"#).expect("writable");

        let storage = FileStorage::new(&path);
        let error = storage.load().expect_err("a future version must not load");
        assert!(error.to_string().contains("unsupported version: 99"));
    }

    #[test]
    fn a_corrupt_file_names_itself_in_the_error() {
        let dir = TempDir::new("corrupt");
        let path = dir.file("settings.conf");
        std::fs::write(&path, "not json").expect("writable");

        let storage = FileStorage::new(&path);
        let error = storage.load().expect_err("a corrupt file must not load");
        assert!(error.to_string().contains("settings.conf"));
    }

    #[test]
    fn the_default_path_is_the_one_pyatv_uses() {
        let path = FileStorage::default_path().expect("HOME is set in the test environment");
        assert!(path.ends_with(".pyatv.conf"));
    }
}

#[cfg(all(test, unix))]
mod permission_tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::FileStorage;
    use super::tests::{TempDir, config};
    use crate::storage::Storage;

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path)
            .expect("the file must exist")
            .permissions()
            .mode()
            & 0o7777
    }

    /// A file the user locked down must not be widened by a save.
    ///
    /// The atomic write creates a sibling at the umask default — `0644` on a typical box — and
    /// renames it over the real file, which carries that mode across. Every device credential
    /// lives in this file.
    #[test]
    fn saving_preserves_an_existing_files_permissions() {
        let dir = TempDir::new("permissions-existing");
        let path = dir.file("settings.conf");

        let storage = FileStorage::new(&path);
        storage
            .update_settings(&config("companion-id"))
            .expect("update must succeed");
        storage.save().expect("save must succeed");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod must succeed");

        let storage = FileStorage::new(&path);
        storage.load().expect("load must succeed");
        storage
            .update_settings(&config("another-id"))
            .expect("update must succeed");
        storage.save().expect("save must succeed");

        assert_eq!(mode_of(&path), 0o600, "the user's mode must survive a save");
    }

    /// A file this crate creates starts at `0600`, not at whatever the umask happens to allow.
    #[test]
    fn a_newly_created_settings_file_is_owner_only() {
        let dir = TempDir::new("permissions-new");
        let path = dir.file("settings.conf");

        let storage = FileStorage::new(&path);
        storage
            .update_settings(&config("companion-id"))
            .expect("update must succeed");
        storage.save().expect("save must succeed");

        assert_eq!(mode_of(&path), 0o600, "credentials are not world-readable");
    }
}
